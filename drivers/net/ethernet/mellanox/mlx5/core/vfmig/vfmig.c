// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/* Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved. */

/*
 * mlx5 host-driver-side VF migration / CRIU restore - control plane.
 * See vfmig.h for the architecture overview.
 *
 * This patch adds the per-PF char device that userspace opens to drive
 * migration of that PF's VFs. Each PF mlx5_core gets a cdev at
 * /dev/mlx5_vfmig/<pf-bdf>; VFs are skipped. The ioctl surface is a
 * stub (-ENOTTY) here -- later patches hang the SAVE / LOAD and per-VF
 * tracking commands off it.
 */

#include <linux/anon_inodes.h>
#include <linux/bitmap.h>
#include <linux/bitops.h>
#include <linux/cdev.h>
#include <linux/crc32.h>
#include <linux/device.h>
#include <linux/device/class.h>
#include <linux/dma-mapping.h>
#include <linux/err.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/highmem.h>
#include <linux/idr.h>
#include <linux/kdev_t.h>
#include <linux/kref.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/pci.h>
#include <linux/rwsem.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/uuid.h>
#include <linux/mlx5/device.h>
#include <linux/mlx5/driver.h>
#include <linux/mlx5/vport.h>
#include <uapi/linux/mlx5_vfmig.h>

#include "mlx5_core.h"
#include "vfmig.h"
#include "vfmig_iova.h"

/* Char-device major/minor range shared by all per-PF vfmig cdevs. */
#define MLX5_VFMIG_MAX_DEVICES 256

static dev_t mlx5_vfmig_devt;
static struct class *mlx5_vfmig_class;
static DEFINE_IDA(mlx5_vfmig_minor_ida);

/*
 * Upper bound on a SAVE snapshot, from the width of save_vhca_state_in.size.
 * A firmware-reported size beyond this is treated as corruption.
 */
#define VFMIG_MAX_SAVE_SIZE \
	(BIT_ULL(__mlx5_bit_sz(save_vhca_state_in, size)) - 1)

/*
 * Wire-format record header prefixing the SAVE stream, byte-compatible
 * with the VFIO mlx5 variant driver's migration header
 * (drivers/vfio/pci/mlx5/cmd.h:mlx5_vf_migration_header) so a saved blob
 * can later be replayed through LOAD_VHCA_STATE.
 */
struct vfmig_wire_header {
	__le64 record_size;
	__le32 flags;
	__le32 tag;
};

#define VFMIG_WIRE_TAG_FW_DATA		0

/*
 * vfmig-private wire records prefixing the FW_DATA payload on a tracked
 * VF's SAVE stream. A tracked source's blob is:
 *
 *   [STREAM_HEADER]  1x  { magic, version, num_pages, manifest_crc32,
 *                          num_user_pages }
 *   [HOST_PAGE]      Nx  one per deterministic-IOVA registry entry, in
 *                        IOVA-ascending order, carrying page contents
 *   [HOST_USER_PAGE] Mx  one per retagged external (USER_PAGE) entry,
 *                        identity-only (kind, fw_id, iova, len); no
 *                        contents -- the umem pages are CRIU's to
 *                        restore. M == 0 until the source-side retag
 *                        callsites land, so this record is absent on a
 *                        blob produced before then.
 *   [HOST_KOBJ]      Kx  one per kernel object a driver on the VF
 *                        recorded (kind, key, fw id); see "Kernel
 *                        objects" in vfmig_iova.h. Not counted in the
 *                        STREAM_HEADER nor folded into its CRC, so a
 *                        blob with K == 0 is unchanged.
 *   [FW_DATA]        1x  the SAVE_VHCA_STATE firmware blob
 *
 * The HOST_PAGE records are replayed into the destination's per-VF IOVA
 * domain (vfmig_iova_replay_page) BEFORE the FW_DATA blob is staged, so
 * every IOVA the restored FW state references already maps to a page
 * carrying the source's contents. Without this a migrated VF's cmd ring
 * (and every other control-plane structure) would point at fresh zeroed
 * pages and the VF would fail to bring up after LOAD.
 *
 * An untracked source emits only the FW_DATA record (num_pages == 0,
 * no STREAM_HEADER / HOST_PAGE prefix); such a blob stays byte-compatible
 * with the pre-slice-8 wire format.
 *
 * Magic "VMIG" / tags "HS" (host-stream) and "HB" (host-buffer) are well
 * clear of the VFIO mlx5 {0, 1} tag range. Neither is OPTIONAL: a
 * HOST_PAGE-bearing blob fed to a parser that does not understand the tag
 * must fail loudly, because silently dropping the IOVA payload would
 * yield a successful LOAD followed by a dead VHCA.
 */
#define VFMIG_WIRE_MAGIC		0x564D4947 /* "VMIG" little-endian */
#define VFMIG_STREAM_VERSION		1
#define VFMIG_WIRE_TAG_STREAM_HEADER	0x4853
#define VFMIG_WIRE_TAG_HOST_PAGE	0x4842
#define VFMIG_WIRE_TAG_HOST_USER_PAGE	0x4855
#define VFMIG_WIRE_TAG_HOST_KOBJ	0x484B
#define VFMIG_HOST_PAGE_MAX_LEN		(16ULL << 20)

struct vfmig_stream_header {
	__le32 magic;
	__le32 version;
	__le64 num_pages;
	__le32 manifest_crc32;
	__le32 num_user_pages;
};

struct vfmig_host_page_record {
	__le32 slot_id;
	__le32 flags;
	__le64 instance_key;
	__le64 iova;
	__le64 len;
};

/*
 * Identity-only record for one external (USER_PAGE) registry entry.
 * Unlike HOST_PAGE it carries no page contents: @instance_key encodes
 * VFMIG_HUOBJ_KEY(kind, fw_id), and (@iova, @len) pin the source-side
 * IOVA window the destination will replay as an awaiting-bind
 * placeholder. @flags / @reserved must be zero.
 */
struct vfmig_host_user_page_record {
	__le32 flags;
	__le32 reserved;
	__le64 instance_key;
	__le64 iova;
	__le64 len;
};

/*
 * Identity-only record for one kernel object: @kind is an
 * enum mlx5_vfmig_kobj_kind, @id its non-zero firmware number. @flags
 * must be zero.
 */
struct vfmig_host_kobj_record {
	__le32 kind;
	__le32 key;
	__le32 id;
	__le32 flags;
};

/*
 * Detached, fully-staged LOAD_VHCA_STATE payload waiting for the next
 * mlx5_core probe of a VF to apply it. Populated when a LOAD anon-inode
 * fd is closed after a complete blob was written; the firmware-tied
 * resources (PD/MKEY/DMA mapping) and the backing pages are transferred
 * out of the per-fd load_ctx into here so they outlive the fd. Consumed
 * (and destroyed) by mlx5_vfmig_vf_apply_pending_load() from the VF's
 * probe path in mlx5_function_enable(). See vfmig_vf_load_destroy().
 */
struct mlx5_vfmig_vf_load {
	u32 vf_id;
	u16 vhca_id;
	u32 pdn;
	bool pd_allocated;
	u32 *mkey_in;		/* alloc_mkey_in() buffer; NULL if no MKEY */
	u32 mkey;
	bool mkey_created;
	bool dma_mapped;
	struct dma_iova_state dma_state;
	struct page **pages;
	u32 npages;
	u64 record_size;	/* bytes inside @pages the FW should consume */
};

/**
 * struct mlx5_vfmig_pf - per-PF vfmig control-plane state
 * @kref:    refcount; drops the last reference from an open fd or the
 *           driver-remove path, whichever comes last.
 * @lock:    guards @dead / @pf_mdev against concurrent ioctls.
 * @pf_mdev: owning PF mlx5_core, NULLed on driver remove.
 * @dead:    set once the PF is being removed; ioctls then fail -ENODEV.
 * @cdev:    the /dev/mlx5_vfmig/<bdf> character device.
 * @minor:   minor number allocated from mlx5_vfmig_minor_ida.
 * @max_vfs: size of @restored / @pending_load (PF's VF capacity at init).
 * @restored: per-VF "restored" latch, indexed by SR-IOV VF id. Set via
 *           MARK_RESTORED or when a LOAD fd stages a complete blob, read
 *           back via QUERY_VF, and consumed by the VF's next probe to
 *           skip INIT_HCA. Accessed with atomic bitops; NULL when
 *           @max_vfs is 0.
 * @pending_load: per-VF staged LOAD_VHCA_STATE slots, indexed by VF id.
 *           A non-NULL entry is applied (and freed) by the VF's next
 *           probe. Mutated under @ctxs_lock. NULL array when @max_vfs 0.
 * @vf_uuid: per-VF orchestrator-stamped identity tag, indexed by VF id.
 *           Stamped via SET_VF_UUID, read back via QUERY_VF, cleared by
 *           SET_VF_UUID(F_CLEAR) or on SR-IOV teardown. Mutated under
 *           @ctxs_lock. NULL when
 *           @max_vfs is 0.
 * @iova_dom: per-VF deterministic IOVA domain, indexed by VF id. A
 *           non-NULL entry means the VF is "tracked": a fixed-IOVA
 *           arena is reserved on its managed DMA-IOMMU domain (see
 *           vfmig_iova.c). Installed
 *           via SET_TRACKED, read back as @tracked via QUERY_VF, torn
 *           down on SR-IOV teardown / PF unload. Mutated under
 *           @ctxs_lock. NULL array when @max_vfs is 0.
 * @ctxs_lock: mutex protecting @save_ctxs / @load_ctxs list mutations,
 *           @pending_load slot install/take, @vf_uuid stamping, and
 *           @iova_dom slot publish/take.
 * @save_ctxs: open SAVE_VHCA_STATE sessions (struct mlx5_vfmig_save_ctx).
 * @load_ctxs: open LOAD_VHCA_STATE sessions (struct mlx5_vfmig_load_ctx).
 */
struct mlx5_vfmig_pf {
	struct kref		kref;
	struct rw_semaphore	lock;
	struct mlx5_core_dev	*pf_mdev;
	bool			dead;
	struct cdev		cdev;
	int			minor;
	u16			max_vfs;
	unsigned long		*restored;
	struct mlx5_vfmig_vf_load **pending_load;
	uuid_t			*vf_uuid;
	struct vfmig_iova_domain **iova_dom;
	struct mutex		ctxs_lock; /* guards save_ctxs/load_ctxs */
	struct list_head	save_ctxs;
	struct list_head	load_ctxs;
};

static void vfmig_pf_release(struct kref *kref)
{
	struct mlx5_vfmig_pf *vfmig =
		container_of(kref, struct mlx5_vfmig_pf, kref);

	WARN_ON(!list_empty(&vfmig->save_ctxs));
	WARN_ON(!list_empty(&vfmig->load_ctxs));
	mutex_destroy(&vfmig->ctxs_lock);
	bitmap_free(vfmig->restored);
	kfree(vfmig->pending_load);
	kfree(vfmig->vf_uuid);
	kfree(vfmig->iova_dom);
	ida_free(&mlx5_vfmig_minor_ida, vfmig->minor);
	kfree(vfmig);
}

static void vfmig_pf_get(struct mlx5_vfmig_pf *vfmig)
{
	kref_get(&vfmig->kref);
}

static void vfmig_pf_put(struct mlx5_vfmig_pf *vfmig)
{
	kref_put(&vfmig->kref, vfmig_pf_release);
}

static int vfmig_open(struct inode *inode, struct file *filp)
{
	struct mlx5_vfmig_pf *vfmig =
		container_of(inode->i_cdev, struct mlx5_vfmig_pf, cdev);

	vfmig_pf_get(vfmig);
	filp->private_data = vfmig;

	return 0;
}

static int vfmig_release(struct inode *inode, struct file *filp)
{
	struct mlx5_vfmig_pf *vfmig = filp->private_data;

	vfmig_pf_put(vfmig);

	return 0;
}

/* -------- ioctl handlers ------------------------------------------------- */

/*
 * QUERY_HCA_CAP(other_function=1) - PF-side query of a VF's vhca_id.
 * Mirrors mlx5vf_cmd_get_vhca_id() in drivers/vfio/pci/mlx5/cmd.c.
 */
static int vfmig_query_vhca_id(struct mlx5_core_dev *pf_mdev,
			       u16 function_id, u16 *vhca_id)
{
	u32 in[MLX5_ST_SZ_DW(query_hca_cap_in)] = {};
	void *out;
	int out_size;
	int ret;

	out_size = MLX5_ST_SZ_BYTES(query_hca_cap_out);
	out = kzalloc(out_size, GFP_KERNEL);
	if (!out)
		return -ENOMEM;

	MLX5_SET(query_hca_cap_in, in, opcode, MLX5_CMD_OP_QUERY_HCA_CAP);
	MLX5_SET(query_hca_cap_in, in, other_function, 1);
	MLX5_SET(query_hca_cap_in, in, function_id, function_id);
	MLX5_SET(query_hca_cap_in, in, op_mod,
		 MLX5_SET_HCA_CAP_OP_MOD_GENERAL_DEVICE << 1 |
		 HCA_CAP_OPMOD_GET_CUR);

	ret = mlx5_cmd_exec_inout(pf_mdev, query_hca_cap, in, out);
	if (ret)
		goto out;

	*vhca_id = MLX5_GET(query_hca_cap_out, out,
			    capability.cmd_hca_cap.vhca_id);
out:
	kfree(out);
	return ret;
}

static long vfmig_ioc_get_vhca_id(struct mlx5_vfmig_pf *vfmig,
				  void __user *uarg)
{
	struct mlx5_vfmig_get_vhca_id arg;
	struct mlx5_core_sriov *sriov;
	u16 vhca_id;
	int err;

	if (copy_from_user(&arg, uarg, sizeof(arg)))
		return -EFAULT;
	if (arg.reserved)
		return -EINVAL;

	sriov = &vfmig->pf_mdev->priv.sriov;
	if (arg.vf_id >= sriov->num_vfs)
		return -EINVAL;

	/* SR-IOV VF index @vf_id maps to function_id vf_id + 1. */
	err = vfmig_query_vhca_id(vfmig->pf_mdev, arg.vf_id + 1, &vhca_id);
	if (err)
		return err;

	arg.vhca_id = vhca_id;
	if (copy_to_user(uarg, &arg, sizeof(arg)))
		return -EFAULT;

	return 0;
}

static long vfmig_ioc_mark_restored(struct mlx5_vfmig_pf *vfmig,
				    void __user *uarg)
{
	struct mlx5_vfmig_mark_restored arg;
	struct mlx5_core_sriov *sriov;

	if (copy_from_user(&arg, uarg, sizeof(arg)))
		return -EFAULT;
	if (arg.flags & ~MLX5_VFMIG_MARK_RESTORED_FLAG_ALL)
		return -EINVAL;

	sriov = &vfmig->pf_mdev->priv.sriov;
	if (arg.vf_id >= sriov->num_vfs || arg.vf_id >= vfmig->max_vfs)
		return -EINVAL;

	/*
	 * Defer-resume request (snapshot-ordering restore mirror): the next
	 * probe applies LOAD_VHCA_STATE but leaves the VHCA parked (STOP) for
	 * a later RESUME_VHCA. Stamp it before the restored latch below so a
	 * VF whose restored bit was already installed (e.g. by the LOAD
	 * ioctl's close()) still honors the hint rather than losing it.
	 */
	sriov->vfs_ctx[arg.vf_id].vfmig_defer_resume =
		(arg.flags & MLX5_VFMIG_MARK_RESTORED_DEFER_RESUME) ? 1 : 0;

	if (test_and_set_bit(arg.vf_id, vfmig->restored)) {
		/*
		 * Latch already set by an earlier MARK_RESTORED or by the LOAD
		 * ioctl's close(). Re-issuing it solely to (re)stamp a flag is
		 * a no-op success; a flagless repeat keeps the -EALREADY
		 * contract for callers that use it as a set-once probe.
		 */
		return arg.flags ? 0 : -EALREADY;
	}

	mlx5_core_dbg(vfmig->pf_mdev, "vfmig: VF %u marked restored%s\n",
		      arg.vf_id,
		      sriov->vfs_ctx[arg.vf_id].vfmig_defer_resume ?
		      " (resume deferred)" : "");

	return 0;
}

/*
 * Resolve VF @vf_id (SR-IOV index under @pf_pdev) to its pci_dev,
 * returning a held reference (drop with pci_dev_put()). We can't derive
 * the VF's BDF directly (pci_iov_virtfn_bus() is not exported to
 * modules, only the ..._devfn variant), so walk the PCI device list and
 * match on (physfn, pci_iov_vf_id). O(num_pci_devs) on a slow ioctl
 * path, which is fine. Returns NULL if no matching VF is present.
 */
static struct pci_dev *vfmig_get_vf_pdev(struct pci_dev *pf_pdev, u32 vf_id)
{
	struct pci_dev *iter = NULL;

	for_each_pci_dev(iter) {
		if (iter->is_virtfn &&
		    iter->physfn == pf_pdev &&
		    pci_iov_vf_id(iter) == (int)vf_id)
			return iter;	/* for_each_pci_dev kept the ref */
	}
	return NULL;
}

/*
 * MLX5_VFMIG_VF_STATE_* for VF @vf_id, read under its device_lock so the
 * driver and its mlx5_core_dev stay put. A VF whose lock is held by a
 * probe or remove in progress reports UNKNOWN instead of waiting, since
 * a wedged probe holds it indefinitely.
 */
static u8 vfmig_vf_state(struct mlx5_vfmig_pf *vfmig, u32 vf_id)
{
	struct pci_dev *pf_pdev = vfmig->pf_mdev->pdev;
	struct mlx5_core_dev *vf_mdev;
	struct pci_dev *vf_pdev;
	u8 state = MLX5_VFMIG_VF_STATE_UNKNOWN;

	vf_pdev = vfmig_get_vf_pdev(pf_pdev, vf_id);
	if (!vf_pdev)
		return state;
	if (!device_trylock(&vf_pdev->dev))
		goto out_put;

	state = 0;
	if (vf_pdev->dev.driver) {
		state |= MLX5_VFMIG_VF_STATE_BOUND;
		/* The PF cdev only exists while the PF is bound to mlx5_core. */
		if (vf_pdev->dev.driver == pf_pdev->dev.driver) {
			vf_mdev = pci_get_drvdata(vf_pdev);
			if (vf_mdev && mlx5_vf_is_restored(vf_mdev)) {
				state |= MLX5_VFMIG_VF_STATE_FROM_LOAD;
				if (mlx5_vf_restore_claimed(vf_mdev))
					state |= MLX5_VFMIG_VF_STATE_CLAIMED;
			}
		}
	}
	device_unlock(&vf_pdev->dev);
out_put:
	pci_dev_put(vf_pdev);
	return state;
}

static long vfmig_ioc_query_vf(struct mlx5_vfmig_pf *vfmig,
			       void __user *uarg)
{
	struct mlx5_vfmig_query_vf arg;
	struct mlx5_core_sriov *sriov;
	u16 vhca_id;
	int err;

	if (copy_from_user(&arg, uarg, sizeof(arg)))
		return -EFAULT;

	sriov = &vfmig->pf_mdev->priv.sriov;
	arg.num_vfs = sriov->num_vfs;
	arg.tracked = 0;
	arg.vf_state = 0;
	memset(arg.reserved_out, 0, sizeof(arg.reserved_out));

	if (arg.vf_id >= sriov->num_vfs) {
		arg.vhca_id = 0;
		arg.restored = 0;
		export_uuid(arg.vf_uuid, &uuid_null);
		if (copy_to_user(uarg, &arg, sizeof(arg)))
			return -EFAULT;
		return -ERANGE;
	}

	err = vfmig_query_vhca_id(vfmig->pf_mdev, arg.vf_id + 1, &vhca_id);
	if (err)
		return err;

	arg.vhca_id = vhca_id;
	arg.restored = (arg.vf_id < vfmig->max_vfs &&
			test_bit(arg.vf_id, vfmig->restored)) ? 1 : 0;
	arg.vf_state = vfmig_vf_state(vfmig, arg.vf_id);

	/*
	 * Serialise the 16-byte read against a concurrent SET_VF_UUID and
	 * the @tracked read against a concurrent SET_TRACKED publish/take.
	 */
	mutex_lock(&vfmig->ctxs_lock);
	if (arg.vf_id < vfmig->max_vfs) {
		export_uuid(arg.vf_uuid, &vfmig->vf_uuid[arg.vf_id]);
		arg.tracked = vfmig->iova_dom[arg.vf_id] ? 1 : 0;
	} else {
		export_uuid(arg.vf_uuid, &uuid_null);
	}
	mutex_unlock(&vfmig->ctxs_lock);

	if (copy_to_user(uarg, &arg, sizeof(arg)))
		return -EFAULT;

	return 0;
}

/*
 * Return the VF id whose slot holds @uuid, or -1 if none does. Caller
 * holds vfmig->ctxs_lock.
 */
static int vfmig_uuid_holder_locked(struct mlx5_vfmig_pf *vfmig,
				    const uuid_t *uuid)
{
	u16 i;

	for (i = 0; i < vfmig->max_vfs; i++)
		if (uuid_equal(&vfmig->vf_uuid[i], uuid))
			return i;
	return -1;
}

/*
 * MLX5_VFMIG_IOC_SET_VF_UUID: stamp the orchestrator's 16-byte identity
 * tag onto VF @vf_id. Set-once until SR-IOV teardown: a first stamp
 * records the UUID, a same-UUID re-stamp is an idempotent no-op, and a
 * different-UUID stamp is rejected -EBUSY (guards against re-tagging a
 * slot that already carries a workload identity). A UUID held by another
 * VF of this PF is rejected -EEXIST, so QUERY_VF never reports the same
 * UUID on two VFs. uuid_null is the "unset" sentinel and is rejected as
 * a write.
 *
 * With MLX5_VFMIG_SET_VF_UUID_F_CLEAR, @vf_uuid is the UUID the caller
 * expects the slot to hold, and the slot is zeroed only on a match.
 * Nothing but QUERY_VF reads the tag, so this is safe on a bound VF.
 */
static long vfmig_ioc_set_vf_uuid(struct mlx5_vfmig_pf *vfmig,
				  void __user *uarg)
{
	struct mlx5_core_dev *pf_mdev = vfmig->pf_mdev;
	struct mlx5_vfmig_set_vf_uuid arg;
	struct mlx5_core_sriov *sriov;
	uuid_t new_uuid;
	uuid_t *slot;
	int err = 0;

	if (copy_from_user(&arg, uarg, sizeof(arg)))
		return -EFAULT;
	if (arg.flags & ~MLX5_VFMIG_SET_VF_UUID_FLAG_ALL)
		return -EINVAL;
	import_uuid(&new_uuid, arg.vf_uuid);
	if (uuid_is_null(&new_uuid))
		return -EINVAL;

	sriov = &pf_mdev->priv.sriov;
	if (arg.vf_id >= sriov->num_vfs || arg.vf_id >= vfmig->max_vfs)
		return -EINVAL;

	slot = &vfmig->vf_uuid[arg.vf_id];

	mutex_lock(&vfmig->ctxs_lock);
	if (arg.flags & MLX5_VFMIG_SET_VF_UUID_F_CLEAR) {
		if (uuid_is_null(slot)) {
			err = -ENOENT;
		} else if (!uuid_equal(slot, &new_uuid)) {
			mlx5_core_warn(pf_mdev,
				       "vfmig: SET_VF_UUID vf %u clear rejected: a different UUID is stamped\n",
				       arg.vf_id);
			err = -EBUSY;
		} else {
			uuid_copy(slot, &uuid_null);
			mlx5_core_info(pf_mdev,
				       "vfmig: SET_VF_UUID vf %u cleared\n",
				       arg.vf_id);
		}
	} else if (uuid_is_null(slot)) {
		int holder = vfmig_uuid_holder_locked(vfmig, &new_uuid);

		if (holder >= 0) {
			mlx5_core_warn(pf_mdev,
				       "vfmig: SET_VF_UUID vf %u rejected: vf %d already holds this UUID\n",
				       arg.vf_id, holder);
			err = -EEXIST;
		} else {
			uuid_copy(slot, &new_uuid);
			mlx5_core_info(pf_mdev,
				       "vfmig: SET_VF_UUID vf %u stamped\n",
				       arg.vf_id);
		}
	} else if (uuid_equal(slot, &new_uuid)) {
		/* Idempotent same-UUID re-stamp; no log line. */
	} else {
		mlx5_core_warn(pf_mdev,
			       "vfmig: SET_VF_UUID vf %u rejected: a different UUID is already stamped\n",
			       arg.vf_id);
		err = -EBUSY;
	}
	mutex_unlock(&vfmig->ctxs_lock);
	return err;
}

/*
 * MLX5_VFMIG_IOC_SET_TRACKED: couple a per-VF deterministic IOVA domain
 * to VF @vf_id. The domain pointer in iova_dom[vf_id] IS the "tracked"
 * state -- non-NULL means a fixed-IOVA arena is reserved on the VF's
 * managed DMA-IOMMU domain (see vfmig_iova.c).
 *
 * The VF must be unbound: we hold the VF pci_dev's device_lock to read
 * ->dev.driver atomically with the reserve/release, so the state and any
 * concurrent driver probe/remove see consistent ordering. On enable we
 * create the domain (reserve the arena), then publish the pointer under
 * ctxs_lock; on disable we take the pointer under ctxs_lock and NULL it.
 * The domain is always created/destroyed outside ctxs_lock (the iommu
 * core takes group locks and may sleep) but the pointer publish/take is
 * under it, matching the QUERY_VF @tracked read.
 *
 * Idempotent toggles (already in the requested state) are silent no-ops.
 * The "already N, no-op" line is mlx5_core_info on purpose: a SET_TRACKED
 * that silently no-ops is the classic symptom of userspace run against a
 * stale mlx5_core.ko, and a default-visible breadcrumb makes the version
 * skew easy to spot.
 */
static long vfmig_ioc_set_tracked(struct mlx5_vfmig_pf *vfmig,
				  void __user *uarg)
{
	struct mlx5_core_dev *pf_mdev = vfmig->pf_mdev;
	struct vfmig_iova_domain *new_dom = NULL;
	struct vfmig_iova_domain *old_dom = NULL;
	struct mlx5_vfmig_set_tracked arg;
	struct mlx5_core_sriov *sriov;
	struct pci_dev *vf_pdev;
	bool desired, tracked;
	int err = 0;

	if (copy_from_user(&arg, uarg, sizeof(arg)))
		return -EFAULT;
	if (arg.flags || arg.reserved)
		return -EINVAL;
	if (arg.enable > 1)
		return -EINVAL;

	sriov = &pf_mdev->priv.sriov;
	if (arg.vf_id >= sriov->num_vfs || arg.vf_id >= vfmig->max_vfs)
		return -EINVAL;

	desired = (arg.enable == 1);

	mutex_lock(&vfmig->ctxs_lock);
	tracked = vfmig->iova_dom[arg.vf_id];
	mutex_unlock(&vfmig->ctxs_lock);

	if (tracked == desired) {
		mlx5_core_info(pf_mdev,
			       "vfmig: SET_TRACKED vf %u: already %d, no-op\n",
			       arg.vf_id, desired);
		return 0;
	}

	vf_pdev = vfmig_get_vf_pdev(pf_mdev->pdev, arg.vf_id);
	if (!vf_pdev) {
		mlx5_core_warn(pf_mdev,
			       "vfmig: SET_TRACKED vf %u: VF pci_dev lookup failed\n",
			       arg.vf_id);
		return -ENODEV;
	}

	device_lock(&vf_pdev->dev);
	if (vf_pdev->dev.driver) {
		mlx5_core_warn(pf_mdev,
			       "vfmig: SET_TRACKED vf %u rejected: VF is bound to %s (must be unbound first)\n",
			       arg.vf_id, vf_pdev->dev.driver->name);
		err = -EBUSY;
		goto out_unlock;
	}

	if (desired) {
		err = vfmig_iova_domain_create(vf_pdev, arg.vf_id, &new_dom);
		if (err) {
			mlx5_core_warn(pf_mdev,
				       "vfmig: SET_TRACKED vf %u: iova_domain_create failed: %d\n",
				       arg.vf_id, err);
			goto out_unlock;
		}
		mutex_lock(&vfmig->ctxs_lock);
		/*
		 * Belt-and-suspenders: a domain already parked here with
		 * our earlier tracked==0 read is a state-machine bug.
		 * Detect, stash it for destruction, don't leak.
		 */
		if (WARN_ON_ONCE(vfmig->iova_dom[arg.vf_id]))
			old_dom = vfmig->iova_dom[arg.vf_id];
		vfmig->iova_dom[arg.vf_id] = new_dom;
		mutex_unlock(&vfmig->ctxs_lock);
		mlx5_core_info(pf_mdev,
			       "vfmig: vf %u tracked=1, iova domain attached\n",
			       arg.vf_id);
	} else {
		mutex_lock(&vfmig->ctxs_lock);
		old_dom = vfmig->iova_dom[arg.vf_id];
		vfmig->iova_dom[arg.vf_id] = NULL;
		mutex_unlock(&vfmig->ctxs_lock);
		mlx5_core_info(pf_mdev,
			       "vfmig: vf %u tracked=0, iova domain detaching\n",
			       arg.vf_id);
	}

out_unlock:
	device_unlock(&vf_pdev->dev);
	pci_dev_put(vf_pdev);

	/*
	 * Destroy the old domain outside device_lock: domain_destroy
	 * detaches via iommu_detach_device (iommu group locks) and frees
	 * the domain, none of which benefits from holding device_lock and
	 * avoids any device-lock vs iommu-group ordering hazards.
	 */
	if (old_dom)
		vfmig_iova_domain_destroy(old_dom);
	return err;
}

/*
 * Gating capabilities for the VF migratable bit. The PF mdev itself
 * must report both `migration` and `vhca_resource_manager` -- matches
 * what mlx5_devlink_port_fn_migratable_set checks before letting
 * userspace flip the per-VF migratable bit. Returns 0 if supported,
 * -EOPNOTSUPP otherwise.
 */
static int vfmig_check_pf_migration_caps(struct mlx5_core_dev *pf_mdev)
{
	if (!MLX5_CAP_GEN(pf_mdev, migration)) {
		mlx5_core_warn(pf_mdev,
			       "vfmig: PF firmware does not advertise migration capability\n");
		return -EOPNOTSUPP;
	}
	if (!MLX5_CAP_GEN(pf_mdev, vhca_resource_manager)) {
		mlx5_core_warn(pf_mdev,
			       "vfmig: PF firmware does not advertise vhca_resource_manager\n");
		return -EOPNOTSUPP;
	}

	return 0;
}

/*
 * Pre-bind helper: idempotently set HCA_CAP_2.migratable=1 on @vf_id.
 * The firmware only accepts this modify-cap while the VF is unbound
 * (no ENABLE_HCA issued yet); on an already-probed VF it returns
 * "bad resource state". The bit is intentionally never cleared again:
 * a VF migration-enabled once stays so for the SR-IOV provisioning.
 *
 * The vport number for VF index @vf_id under standard SR-IOV is
 * @vf_id + 1 (vport 0 is the PF).
 */
static int vfmig_set_vf_migratable(struct mlx5_core_dev *pf_mdev, u32 vf_id)
{
	int query_sz = MLX5_ST_SZ_BYTES(query_hca_cap_out);
	u16 vport = vf_id + 1;
	void *query_ctx;
	void *hca_caps;
	int err;

	query_ctx = kzalloc(query_sz, GFP_KERNEL);
	if (!query_ctx)
		return -ENOMEM;

	err = mlx5_vport_get_other_func_cap(pf_mdev, vport, query_ctx,
					    MLX5_CAP_GENERAL_2);
	if (err) {
		mlx5_core_warn(pf_mdev,
			       "vfmig: query GENERAL_2 cap for vf %u (vport %u) failed: %d\n",
			       vf_id, vport, err);
		goto out;
	}

	hca_caps = MLX5_ADDR_OF(query_hca_cap_out, query_ctx, capability);
	if (MLX5_GET(cmd_hca_cap_2, hca_caps, migratable)) {
		err = 0;
		goto out;
	}

	MLX5_SET(cmd_hca_cap_2, hca_caps, migratable, 1);
	err = mlx5_vport_set_other_func_cap(pf_mdev, hca_caps, vport,
					    MLX5_SET_HCA_CAP_OP_MOD_GENERAL_DEVICE2);
	if (err) {
		mlx5_core_warn(pf_mdev,
			       "vfmig: set GENERAL_2.migratable=1 for vf %u (vport %u) failed: %d (VF must be unbound)\n",
			       vf_id, vport, err);
		goto out;
	}
	mlx5_core_info(pf_mdev,
		       "vfmig: enabled migratable cap for vf %u (vport %u)\n",
		       vf_id, vport);
out:
	kfree(query_ctx);
	return err;
}

static long vfmig_ioc_enable_migratable(struct mlx5_vfmig_pf *vfmig,
					void __user *uarg)
{
	struct mlx5_vfmig_enable_migratable arg;
	struct mlx5_core_sriov *sriov;
	int err;

	if (copy_from_user(&arg, uarg, sizeof(arg)))
		return -EFAULT;
	if (arg.reserved)
		return -EINVAL;

	sriov = &vfmig->pf_mdev->priv.sriov;
	if (arg.vf_id >= sriov->num_vfs)
		return -EINVAL;

	err = vfmig_check_pf_migration_caps(vfmig->pf_mdev);
	if (err)
		return err;

	return vfmig_set_vf_migratable(vfmig->pf_mdev, arg.vf_id);
}

/*
 * Raw firmware SUSPEND_VHCA on a VF's @vhca_id, issued by the PF with
 * other_function implied by @vhca_id. @op_mod selects the
 * initiator/responder direction. This is the primitive the suspend
 * ladder is built from.
 */
static int vfmig_cmd_suspend_vhca(struct mlx5_core_dev *pf_mdev, u16 vhca_id,
				  u16 op_mod)
{
	u32 out[MLX5_ST_SZ_DW(suspend_vhca_out)] = {};
	u32 in[MLX5_ST_SZ_DW(suspend_vhca_in)] = {};

	MLX5_SET(suspend_vhca_in, in, opcode, MLX5_CMD_OP_SUSPEND_VHCA);
	MLX5_SET(suspend_vhca_in, in, vhca_id, vhca_id);
	MLX5_SET(suspend_vhca_in, in, op_mod, op_mod);

	return mlx5_cmd_exec_inout(pf_mdev, suspend_vhca, in, out);
}

static int vfmig_cmd_resume_vhca(struct mlx5_core_dev *pf_mdev, u16 vhca_id,
				 u16 op_mod)
{
	u32 out[MLX5_ST_SZ_DW(resume_vhca_out)] = {};
	u32 in[MLX5_ST_SZ_DW(resume_vhca_in)] = {};

	MLX5_SET(resume_vhca_in, in, opcode, MLX5_CMD_OP_RESUME_VHCA);
	MLX5_SET(resume_vhca_in, in, vhca_id, vhca_id);
	MLX5_SET(resume_vhca_in, in, op_mod, op_mod);

	return mlx5_cmd_exec_inout(pf_mdev, resume_vhca, in, out);
}

/* Park one ladder step deeper from state @s (RUNNING->P2P or P2P->STOP). */
static int vfmig_dp_suspend_step(struct mlx5_core_dev *pf_mdev, u16 vhca_id,
				 u8 s)
{
	u16 op_mod = (s == MLX5_VFMIG_DP_RUNNING) ?
		MLX5_SUSPEND_VHCA_IN_OP_MOD_SUSPEND_INITIATOR :
		MLX5_SUSPEND_VHCA_IN_OP_MOD_SUSPEND_RESPONDER;
	int err = vfmig_cmd_suspend_vhca(pf_mdev, vhca_id, op_mod);

	if (err)
		mlx5_core_warn(pf_mdev,
			       "vfmig: SUSPEND_VHCA(%s) vhca_id 0x%04x failed: %d\n",
			       s == MLX5_VFMIG_DP_RUNNING ? "INITIATOR" : "RESPONDER",
			       vhca_id, err);
	return err;
}

/* Unpark one ladder step shallower from state @s (STOP->P2P or P2P->RUNNING). */
static int vfmig_dp_resume_step(struct mlx5_core_dev *pf_mdev, u16 vhca_id,
				u8 s)
{
	u16 op_mod = (s == MLX5_VFMIG_DP_STOP) ?
		MLX5_RESUME_VHCA_IN_OP_MOD_RESUME_RESPONDER :
		MLX5_RESUME_VHCA_IN_OP_MOD_RESUME_INITIATOR;
	int err = vfmig_cmd_resume_vhca(pf_mdev, vhca_id, op_mod);

	if (err)
		mlx5_core_warn(pf_mdev,
			       "vfmig: RESUME_VHCA(%s) vhca_id 0x%04x failed: %d\n",
			       s == MLX5_VFMIG_DP_STOP ? "RESPONDER" : "INITIATOR",
			       vhca_id, err);
	return err;
}

/*
 * Walk the datapath ladder from @from to @to one firmware step at a time
 * (deeper via SUSPEND, shallower via RESUME), latching the depth actually
 * reached in *@reached. On a step failure the walk stops and *@reached
 * holds the truthful intermediate depth, so the caller can recover with
 * the inverse operation. Returns 0 or the first firmware error; *@reached
 * is always set.
 */
static int vfmig_dp_transition(struct mlx5_core_dev *pf_mdev, u16 vhca_id,
			       u8 from, u8 to, u8 *reached)
{
	int err = 0;
	u8 s = from;

	while (s < to) {		/* deeper suspend */
		err = vfmig_dp_suspend_step(pf_mdev, vhca_id, s);
		if (err)
			break;
		s++;
	}
	while (s > to) {		/* shallower resume */
		err = vfmig_dp_resume_step(pf_mdev, vhca_id, s);
		if (err)
			break;
		s--;
	}

	*reached = s;
	return err;
}

/*
 * Read back cmd_hca_cap_2.migratable for @vf_id via
 * QUERY_HCA_CAP(other_function=1), the gate SUSPEND requires. The vport
 * number for VF index @vf_id under standard SR-IOV is @vf_id + 1.
 */
static int vfmig_query_vf_migratable(struct mlx5_core_dev *pf_mdev, u32 vf_id,
				     bool *enabled)
{
	int query_sz = MLX5_ST_SZ_BYTES(query_hca_cap_out);
	u16 vport = vf_id + 1;
	void *query_ctx;
	void *hca_caps;
	int err;

	query_ctx = kzalloc(query_sz, GFP_KERNEL);
	if (!query_ctx)
		return -ENOMEM;

	err = mlx5_vport_get_other_func_cap(pf_mdev, vport, query_ctx,
					    MLX5_CAP_GENERAL_2);
	if (err) {
		mlx5_core_warn(pf_mdev,
			       "vfmig: query GENERAL_2 cap for vf %u (vport %u) failed: %d\n",
			       vf_id, vport, err);
		goto out;
	}

	hca_caps = MLX5_ADDR_OF(query_hca_cap_out, query_ctx, capability);
	*enabled = MLX5_GET(cmd_hca_cap_2, hca_caps, migratable);
out:
	kfree(query_ctx);
	return err;
}

static long vfmig_ioc_suspend_vhca(struct mlx5_vfmig_pf *vfmig,
				   void __user *uarg)
{
	struct mlx5_core_dev *pf_mdev = vfmig->pf_mdev;
	struct mlx5_vfmig_suspend_vhca arg;
	struct mlx5_core_sriov *sriov;
	bool migratable = false;
	u8 cur, target, reached;
	u32 dir;
	u16 vhca_id;
	int err;

	if (copy_from_user(&arg, uarg, sizeof(arg)))
		return -EFAULT;
	if (arg.reserved[0] || arg.reserved[1])
		return -EINVAL;
	dir = arg.flags ? arg.flags : MLX5_VFMIG_DIR_FLAG_ALL;
	if (dir & ~(u32)MLX5_VFMIG_DIR_FLAG_ALL)
		return -EINVAL;

	sriov = &pf_mdev->priv.sriov;
	if (arg.vf_id >= sriov->num_vfs)
		return -EINVAL;

	cur = sriov->vfs_ctx[arg.vf_id].vfmig_dp_state;

	/*
	 * Map the requested direction(s) onto a target depth: suspending the
	 * initiator parks it (RUNNING->P2P); suspending the responder implies
	 * the initiator is already parked and drives to STOP. A responder-only
	 * suspend while still RUNNING is out of order (firmware requires
	 * initiator-first) -- reject it.
	 */
	if ((dir & MLX5_VFMIG_DIR_FLAG_RESPONDER) &&
	    !(dir & MLX5_VFMIG_DIR_FLAG_INITIATOR) &&
	    cur == MLX5_VFMIG_DP_RUNNING)
		return -EINVAL;

	target = cur;
	if ((dir & MLX5_VFMIG_DIR_FLAG_INITIATOR) && target < MLX5_VFMIG_DP_P2P)
		target = MLX5_VFMIG_DP_P2P;
	if (dir & MLX5_VFMIG_DIR_FLAG_RESPONDER)
		target = MLX5_VFMIG_DP_STOP;

	if (target <= cur)		/* already at or past the target */
		return 0;

	err = vfmig_check_pf_migration_caps(pf_mdev);
	if (err)
		return err;

	err = vfmig_query_vf_migratable(pf_mdev, arg.vf_id, &migratable);
	if (err)
		return err;
	if (!migratable) {
		mlx5_core_warn(pf_mdev,
			       "vfmig: vf %u is not migration-enabled (issue ENABLE_MIGRATABLE pre-bind)\n",
			       arg.vf_id);
		return -EOPNOTSUPP;
	}

	err = vfmig_query_vhca_id(pf_mdev, arg.vf_id + 1, &vhca_id);
	if (err)
		return err;

	err = vfmig_dp_transition(pf_mdev, vhca_id, cur, target, &reached);
	sriov->vfs_ctx[arg.vf_id].vfmig_dp_state = reached;
	if (err)
		return err;

	mlx5_core_info(pf_mdev,
		       "vfmig: suspended vf %u (vhca_id 0x%04x) datapath %u->%u\n",
		       arg.vf_id, vhca_id, cur, reached);
	return 0;
}

/*
 * RoCE RX fence: a one-entry DROP table on the VF's own RDMA_RX steering,
 * made the root. It is built from raw firmware commands on the VF's command
 * interface, outside mlx5_core's steering, and is known only by its
 * handles. Level 1, not 0: the level-0 table is the root by default, so a
 * fence left at level 0 would take the root back whenever it was reset.
 */
static void vfmig_rx_fence_destroy(struct mlx5_core_dev *vf, u32 table_id,
				   u32 group_id)
{
	u32 fg_in[MLX5_ST_SZ_DW(destroy_flow_group_in)] = {};
	u32 ft_in[MLX5_ST_SZ_DW(destroy_flow_table_in)] = {};

	MLX5_SET(destroy_flow_group_in, fg_in, opcode, MLX5_CMD_OP_DESTROY_FLOW_GROUP);
	MLX5_SET(destroy_flow_group_in, fg_in, table_type, FS_FT_RDMA_RX);
	MLX5_SET(destroy_flow_group_in, fg_in, table_id, table_id);
	MLX5_SET(destroy_flow_group_in, fg_in, group_id, group_id);
	mlx5_cmd_exec_in(vf, destroy_flow_group, fg_in);

	MLX5_SET(destroy_flow_table_in, ft_in, opcode, MLX5_CMD_OP_DESTROY_FLOW_TABLE);
	MLX5_SET(destroy_flow_table_in, ft_in, table_type, FS_FT_RDMA_RX);
	MLX5_SET(destroy_flow_table_in, ft_in, table_id, table_id);
	mlx5_cmd_exec_in(vf, destroy_flow_table, ft_in);
}

static int vfmig_rx_fence_delete_fte(struct mlx5_core_dev *vf, u32 table_id)
{
	u32 in[MLX5_ST_SZ_DW(delete_fte_in)] = {};

	MLX5_SET(delete_fte_in, in, opcode, MLX5_CMD_OP_DELETE_FLOW_TABLE_ENTRY);
	MLX5_SET(delete_fte_in, in, table_type, FS_FT_RDMA_RX);
	MLX5_SET(delete_fte_in, in, table_id, table_id);
	MLX5_SET(delete_fte_in, in, flow_index, 0);
	return mlx5_cmd_exec_in(vf, delete_fte, in);
}

static int vfmig_rx_fence_create(struct mlx5_core_dev *vf, u32 *table_id,
				 u32 *group_id)
{
	u32 root_in[MLX5_ST_SZ_DW(set_flow_table_root_in)] = {};
	u32 ft_out[MLX5_ST_SZ_DW(create_flow_table_out)] = {};
	u32 fg_out[MLX5_ST_SZ_DW(create_flow_group_out)] = {};
	u32 ft_in[MLX5_ST_SZ_DW(create_flow_table_in)] = {};
	u32 fte_out[MLX5_ST_SZ_DW(set_fte_out)] = {};
	int fte_len = MLX5_ST_SZ_BYTES(set_fte_in);
	int fg_len = MLX5_ST_SZ_BYTES(create_flow_group_in);
	u32 *fg_in, *fte_in;
	void *ctx;
	int err;

	fg_in = kvzalloc(fg_len, GFP_KERNEL);
	fte_in = kvzalloc(fte_len, GFP_KERNEL);
	if (!fg_in || !fte_in) {
		err = -ENOMEM;
		goto out;
	}

	MLX5_SET(create_flow_table_in, ft_in, opcode, MLX5_CMD_OP_CREATE_FLOW_TABLE);
	MLX5_SET(create_flow_table_in, ft_in, table_type, FS_FT_RDMA_RX);
	MLX5_SET(create_flow_table_in, ft_in, flow_table_context.level, 1);
	err = mlx5_cmd_exec_inout(vf, create_flow_table, ft_in, ft_out);
	if (err)
		goto out;
	*table_id = MLX5_GET(create_flow_table_out, ft_out, table_id);

	/* One entry, index 0, with no match criteria: it matches everything. */
	MLX5_SET(create_flow_group_in, fg_in, opcode, MLX5_CMD_OP_CREATE_FLOW_GROUP);
	MLX5_SET(create_flow_group_in, fg_in, table_type, FS_FT_RDMA_RX);
	MLX5_SET(create_flow_group_in, fg_in, table_id, *table_id);
	err = mlx5_cmd_exec(vf, fg_in, fg_len, fg_out, sizeof(fg_out));
	if (err)
		goto destroy_table;
	*group_id = MLX5_GET(create_flow_group_out, fg_out, group_id);

	MLX5_SET(set_fte_in, fte_in, opcode, MLX5_CMD_OP_SET_FLOW_TABLE_ENTRY);
	MLX5_SET(set_fte_in, fte_in, table_type, FS_FT_RDMA_RX);
	MLX5_SET(set_fte_in, fte_in, table_id, *table_id);
	ctx = MLX5_ADDR_OF(set_fte_in, fte_in, flow_context);
	MLX5_SET(flow_context, ctx, group_id, *group_id);
	MLX5_SET(flow_context, ctx, action, MLX5_FLOW_CONTEXT_ACTION_DROP);
	err = mlx5_cmd_exec(vf, fte_in, fte_len, fte_out, sizeof(fte_out));
	if (err)
		goto destroy_group;

	MLX5_SET(set_flow_table_root_in, root_in, opcode, MLX5_CMD_OP_SET_FLOW_TABLE_ROOT);
	MLX5_SET(set_flow_table_root_in, root_in, table_type, FS_FT_RDMA_RX);
	MLX5_SET(set_flow_table_root_in, root_in, table_id, *table_id);
	err = mlx5_cmd_exec_in(vf, set_flow_table_root, root_in);
	if (!err)
		goto out;

	vfmig_rx_fence_delete_fte(vf, *table_id);
destroy_group:
	vfmig_rx_fence_destroy(vf, *table_id, *group_id);
	goto out;
destroy_table:
	vfmig_rx_fence_destroy(vf, *table_id, 0);
out:
	kvfree(fte_in);
	kvfree(fg_in);
	return err;
}

/*
 * Block mlx5_core's steering from taking the RDMA_RX root first, then put
 * the fence there.
 */
static int vfmig_rx_fence_raise(struct mlx5_core_dev *vf, u32 *table_id,
				u32 *group_id)
{
	int err;

	err = mlx5_fs_rdma_rx_fence(vf, true);
	if (err)
		return err;
	err = vfmig_rx_fence_create(vf, table_id, group_id);
	if (err)
		mlx5_fs_rdma_rx_fence(vf, false);
	return err;
}

/*
 * Hand the root back to mlx5_core's own RDMA_RX table, if it has one, then
 * take the fence apart. With no such table, destroying the root leaves the
 * default: every packet goes to its QP. @no_table: a VF restored from an
 * unfenced source has only mlx5_core's steering to release.
 */
static int vfmig_rx_fence_lift(struct mlx5_core_dev *vf, u32 table_id,
			       u32 group_id, bool no_table)
{
	int err;

	if (no_table)
		return mlx5_fs_rdma_rx_fence(vf, false);

	err = vfmig_rx_fence_delete_fte(vf, table_id);
	if (err)
		return err;
	err = mlx5_fs_rdma_rx_fence(vf, false);
	vfmig_rx_fence_destroy(vf, table_id, group_id);
	return err;
}

/*
 * Fence first, so nothing reaches the VF's QPs while mlx5e tears down its
 * steering. -ENODEV from the suspend: mlx5e is not bound, or already
 * suspended; either way this raise suspended nothing. The mlx5_ib release
 * comes last and cannot fail the raise: it has nothing to undo.
 */
static int vfmig_rx_fence_raise_eth(struct mlx5_core_dev *vf,
				    struct mlx5_vfmig_rx_fence *arg)
{
	int err, released = -ENODEV;

	err = vfmig_rx_fence_raise(vf, &arg->table_id, &arg->group_id);
	if (err)
		return err;

	if (arg->flags & MLX5_VFMIG_RX_FENCE_F_ETH_SUSPEND) {
		err = mlx5_adev_eth_suspend(vf, true);
		if (err == -ENODEV) {
			arg->flags &= ~MLX5_VFMIG_RX_FENCE_F_ETH_SUSPEND;
		} else if (err) {
			vfmig_rx_fence_lift(vf, arg->table_id, arg->group_id,
					    false);
			return err;
		}
	}

	if (arg->flags & MLX5_VFMIG_RX_FENCE_F_IB_RELEASE) {
		mlx5_blocking_notifier_call_chain(vf,
						  MLX5_DRIVER_EVENT_VFMIG_IB_RELEASE,
						  &released);
		if (released)
			arg->flags &= ~MLX5_VFMIG_RX_FENCE_F_IB_RELEASE;
	}
	return 0;
}

/* Resume mlx5e before the fence comes down, so a failed resume can be retried. */
static int vfmig_rx_fence_lift_eth(struct mlx5_core_dev *vf,
				   struct mlx5_vfmig_rx_fence *arg)
{
	int err;

	if (arg->flags & MLX5_VFMIG_RX_FENCE_F_ETH_SUSPEND) {
		err = mlx5_adev_eth_suspend(vf, false);
		if (err == -ENODEV)
			arg->flags &= ~MLX5_VFMIG_RX_FENCE_F_ETH_SUSPEND;
		else if (err)
			return err;
	}
	return vfmig_rx_fence_lift(vf, arg->table_id, arg->group_id,
				   arg->flags & MLX5_VFMIG_RX_FENCE_F_NO_TABLE);
}

/*
 * Called without vfmig->lock: the mlx5e suspend takes the VF's devlink lock,
 * which VF probe and devlink reload hold while taking vfmig->lock. A bound
 * VF pins its PF instead, as SR-IOV disable must unbind it first.
 */
static long vfmig_ioc_rx_fence(struct mlx5_vfmig_pf *vfmig, void __user *uarg)
{
	struct mlx5_core_dev *pf_mdev;
	struct mlx5_vfmig_rx_fence arg;
	struct pci_dev *vf_pdev;
	int err;

	if (copy_from_user(&arg, uarg, sizeof(arg)))
		return -EFAULT;
	if (arg.reserved)
		return -EINVAL;
	if (arg.op != MLX5_VFMIG_RX_FENCE_RAISE &&
	    arg.op != MLX5_VFMIG_RX_FENCE_LIFT)
		return -EINVAL;
	if (arg.flags & ~(MLX5_VFMIG_RX_FENCE_F_NO_TABLE |
			  MLX5_VFMIG_RX_FENCE_F_ETH_SUSPEND |
			  MLX5_VFMIG_RX_FENCE_F_IB_RELEASE) ||
	    (arg.flags & MLX5_VFMIG_RX_FENCE_F_NO_TABLE &&
	     arg.op != MLX5_VFMIG_RX_FENCE_LIFT) ||
	    (arg.flags & MLX5_VFMIG_RX_FENCE_F_IB_RELEASE &&
	     arg.op != MLX5_VFMIG_RX_FENCE_RAISE))
		return -EINVAL;

	down_read(&vfmig->lock);
	if (vfmig->dead) {
		up_read(&vfmig->lock);
		return -ENODEV;
	}
	pf_mdev = vfmig->pf_mdev;
	if (arg.vf_id >= pf_mdev->priv.sriov.num_vfs)
		err = -EINVAL;
	else if (pf_mdev->priv.sriov.vfs_ctx[arg.vf_id].vfmig_dp_state !=
		 MLX5_VFMIG_DP_RUNNING)
		err = -EBUSY;
	else
		err = 0;
	vf_pdev = err ? NULL : vfmig_get_vf_pdev(pf_mdev->pdev, arg.vf_id);
	up_read(&vfmig->lock);
	if (err)
		return err;
	if (!vf_pdev)
		return -ENODEV;

	/* The device lock keeps the VF's mlx5_core, and so the PF, bound. */
	device_lock(&vf_pdev->dev);
	if (vf_pdev->dev.driver != pf_mdev->pdev->dev.driver) {
		device_unlock(&vf_pdev->dev);
		pci_dev_put(vf_pdev);
		return -ENODEV;
	}

	if (arg.op == MLX5_VFMIG_RX_FENCE_RAISE)
		err = vfmig_rx_fence_raise_eth(pci_get_drvdata(vf_pdev), &arg);
	else
		err = vfmig_rx_fence_lift_eth(pci_get_drvdata(vf_pdev), &arg);

	if (err)
		mlx5_core_warn(pf_mdev, "vfmig: %s RoCE RX fence on vf %u failed: %d\n",
			       arg.op == MLX5_VFMIG_RX_FENCE_RAISE ? "raising" : "lifting",
			       arg.vf_id, err);
	else
		mlx5_core_info(pf_mdev, "vfmig: RoCE RX fence %s on vf %u (table 0x%x group 0x%x)%s%s\n",
			       arg.op == MLX5_VFMIG_RX_FENCE_RAISE ? "up" : "down",
			       arg.vf_id, arg.table_id, arg.group_id,
			       !(arg.flags & MLX5_VFMIG_RX_FENCE_F_ETH_SUSPEND) ? "" :
			       arg.op == MLX5_VFMIG_RX_FENCE_RAISE ? ", mlx5e suspended" :
			       ", mlx5e resumed",
			       arg.flags & MLX5_VFMIG_RX_FENCE_F_IB_RELEASE ?
			       ", mlx5_ib released" : "");
	device_unlock(&vf_pdev->dev);
	pci_dev_put(vf_pdev);
	if (err)
		return err;

	if (arg.op == MLX5_VFMIG_RX_FENCE_RAISE &&
	    copy_to_user(uarg, &arg, sizeof(arg)))
		return -EFAULT;
	return 0;
}

static long vfmig_ioc_resume_vhca(struct mlx5_vfmig_pf *vfmig,
				  void __user *uarg)
{
	struct mlx5_core_dev *pf_mdev = vfmig->pf_mdev;
	struct mlx5_vfmig_resume_vhca arg;
	struct mlx5_core_sriov *sriov;
	u8 cur, target, reached;
	u32 dir;
	u16 vhca_id;
	int err;

	if (copy_from_user(&arg, uarg, sizeof(arg)))
		return -EFAULT;
	if (arg.reserved[0] || arg.reserved[1])
		return -EINVAL;
	dir = arg.flags ? arg.flags : MLX5_VFMIG_DIR_FLAG_ALL;
	if (dir & ~(u32)MLX5_VFMIG_DIR_FLAG_ALL)
		return -EINVAL;

	sriov = &pf_mdev->priv.sriov;
	if (arg.vf_id >= sriov->num_vfs)
		return -EINVAL;

	cur = sriov->vfs_ctx[arg.vf_id].vfmig_dp_state;

	/*
	 * Map the requested direction(s) onto a target depth: resuming the
	 * responder revives it (STOP->P2P); resuming the initiator drives all
	 * the way to RUNNING. An initiator-only resume while still STOP is out
	 * of order (firmware requires responder-first) -- reject it.
	 */
	if ((dir & MLX5_VFMIG_DIR_FLAG_INITIATOR) &&
	    !(dir & MLX5_VFMIG_DIR_FLAG_RESPONDER) &&
	    cur == MLX5_VFMIG_DP_STOP)
		return -EINVAL;

	target = cur;
	if ((dir & MLX5_VFMIG_DIR_FLAG_RESPONDER) && target > MLX5_VFMIG_DP_P2P)
		target = MLX5_VFMIG_DP_P2P;
	if (dir & MLX5_VFMIG_DIR_FLAG_INITIATOR)
		target = MLX5_VFMIG_DP_RUNNING;

	if (target >= cur)		/* already at or above the target */
		return 0;

	err = vfmig_query_vhca_id(pf_mdev, arg.vf_id + 1, &vhca_id);
	if (err)
		return err;

	err = vfmig_dp_transition(pf_mdev, vhca_id, cur, target, &reached);
	sriov->vfs_ctx[arg.vf_id].vfmig_dp_state = reached;
	if (err)
		return err;

	mlx5_core_info(pf_mdev,
		       "vfmig: resumed vf %u (vhca_id 0x%04x) datapath %u->%u\n",
		       arg.vf_id, vhca_id, cur, reached);
	return 0;
}

/* -------- SAVE_VHCA_STATE: DMA/mkey helpers (cloned from VFIO variant) --- */

/*
 * The helpers below (alloc_mkey_in, create_mkey, register_dma_pages,
 * unregister_dma_pages, alloc_pages, free_pages) are copies of the static
 * helpers in drivers/vfio/pci/mlx5/cmd.c. They are duplicated here so this
 * driver needs no new export boundary into the VFIO variant; a future
 * patch should hoist them into mlx5_core proper and let both consume the
 * shared versions.
 */
static u32 *vfmig_alloc_mkey_in(u32 npages, u32 pdn)
{
	int inlen;
	void *mkc;
	u32 *in;

	inlen = MLX5_ST_SZ_BYTES(create_mkey_in) +
		sizeof(__be64) * round_up(npages, 2);

	in = kvzalloc(inlen, GFP_KERNEL_ACCOUNT);
	if (!in)
		return NULL;

	MLX5_SET(create_mkey_in, in, translations_octword_actual_size,
		 DIV_ROUND_UP(npages, 2));

	mkc = MLX5_ADDR_OF(create_mkey_in, in, memory_key_mkey_entry);
	MLX5_SET(mkc, mkc, access_mode_1_0, MLX5_MKC_ACCESS_MODE_MTT);
	MLX5_SET(mkc, mkc, lr, 1);
	MLX5_SET(mkc, mkc, lw, 1);
	MLX5_SET(mkc, mkc, rr, 1);
	MLX5_SET(mkc, mkc, rw, 1);
	MLX5_SET(mkc, mkc, pd, pdn);
	MLX5_SET(mkc, mkc, bsf_octword_size, 0);
	MLX5_SET(mkc, mkc, qpn, 0xffffff);
	MLX5_SET(mkc, mkc, log_page_size, PAGE_SHIFT);
	MLX5_SET(mkc, mkc, translations_octword_size, DIV_ROUND_UP(npages, 2));
	MLX5_SET64(mkc, mkc, len, npages * PAGE_SIZE);

	return in;
}

static int vfmig_create_mkey(struct mlx5_core_dev *mdev, u32 npages,
			     u32 *mkey_in, u32 *mkey)
{
	int inlen = MLX5_ST_SZ_BYTES(create_mkey_in) +
		sizeof(__be64) * round_up(npages, 2);

	return mlx5_core_create_mkey(mdev, mkey, mkey_in, inlen);
}

static void vfmig_unregister_dma_pages(struct mlx5_core_dev *mdev, u32 npages,
				       u32 *mkey_in,
				       struct dma_iova_state *state,
				       enum dma_data_direction dir)
{
	dma_addr_t addr;
	__be64 *mtt;
	int i;

	if (dma_use_iova(state)) {
		dma_iova_destroy(mdev->device, state, npages * PAGE_SIZE, dir,
				 0);
	} else {
		mtt = (__be64 *)MLX5_ADDR_OF(create_mkey_in, mkey_in,
					     klm_pas_mtt);
		for (i = npages - 1; i >= 0; i--) {
			addr = be64_to_cpu(mtt[i]);
			dma_unmap_page(mdev->device, addr, PAGE_SIZE, dir);
		}
	}
}

static int vfmig_register_dma_pages(struct mlx5_core_dev *mdev, u32 npages,
				    struct page **page_list, u32 *mkey_in,
				    struct dma_iova_state *state,
				    enum dma_data_direction dir)
{
	dma_addr_t addr;
	size_t mapped = 0;
	__be64 *mtt;
	int i, err;

	mtt = (__be64 *)MLX5_ADDR_OF(create_mkey_in, mkey_in, klm_pas_mtt);

	if (dma_iova_try_alloc(mdev->device, state, 0, npages * PAGE_SIZE)) {
		addr = state->addr;
		for (i = 0; i < npages; i++) {
			err = dma_iova_link(mdev->device, state,
					    page_to_phys(page_list[i]), mapped,
					    PAGE_SIZE, dir, 0);
			if (err)
				goto error;
			*mtt++ = cpu_to_be64(addr);
			addr += PAGE_SIZE;
			mapped += PAGE_SIZE;
		}
		err = dma_iova_sync(mdev->device, state, 0, mapped);
		if (err)
			goto error;
	} else {
		for (i = 0; i < npages; i++) {
			addr = dma_map_page(mdev->device, page_list[i], 0,
					    PAGE_SIZE, dir);
			err = dma_mapping_error(mdev->device, addr);
			if (err)
				goto error;
			*mtt++ = cpu_to_be64(addr);
		}
	}
	return 0;

error:
	vfmig_unregister_dma_pages(mdev, i, mkey_in, state, dir);
	return err;
}

static int vfmig_alloc_pages(struct page ***page_list, unsigned int npages)
{
	unsigned int filled, done = 0;
	int i;

	*page_list = kvcalloc(npages, sizeof(struct page *),
			      GFP_KERNEL_ACCOUNT);
	if (!*page_list)
		return -ENOMEM;

	for (;;) {
		filled = alloc_pages_bulk(GFP_KERNEL_ACCOUNT, npages - done,
					  *page_list + done);
		if (!filled)
			goto err;

		done += filled;
		if (done == npages)
			break;
	}

	return 0;
err:
	for (i = 0; i < done; i++)
		__free_page((*page_list)[i]);

	kvfree(*page_list);
	*page_list = NULL;
	return -ENOMEM;
}

static void vfmig_free_pages(struct page **page_list, u32 npages)
{
	int i;

	if (!page_list)
		return;

	for (i = npages - 1; i >= 0; i--)
		__free_page(page_list[i]);

	kvfree(page_list);
}

/*
 * Synchronous QUERY_VHCA_MIGRATION_STATE: single-shot (no incremental, no
 * chunk mode), *@size_out gets required_umem_size in bytes.
 */
static int vfmig_cmd_query_vhca_migration_state(struct mlx5_core_dev *pf_mdev,
						u16 vhca_id, u64 *size_out)
{
	u32 out[MLX5_ST_SZ_DW(query_vhca_migration_state_out)] = {};
	u32 in[MLX5_ST_SZ_DW(query_vhca_migration_state_in)] = {};
	int err;

	MLX5_SET(query_vhca_migration_state_in, in, opcode,
		 MLX5_CMD_OP_QUERY_VHCA_MIGRATION_STATE);
	MLX5_SET(query_vhca_migration_state_in, in, vhca_id, vhca_id);
	MLX5_SET(query_vhca_migration_state_in, in, op_mod, 0);
	MLX5_SET(query_vhca_migration_state_in, in, incremental, 0);
	MLX5_SET(query_vhca_migration_state_in, in, chunk, 0);

	err = mlx5_cmd_exec_inout(pf_mdev, query_vhca_migration_state, in, out);
	if (err)
		return err;

	*size_out = MLX5_GET(query_vhca_migration_state_out, out,
			     required_umem_size);
	return 0;
}

/*
 * Synchronous SAVE_VHCA_STATE. @size is the buffer capacity offered to the
 * firmware (bytes); *@actual_size_out gets the bytes it actually wrote.
 */
static int vfmig_cmd_save_vhca_state(struct mlx5_core_dev *pf_mdev, u16 vhca_id,
				     u32 mkey, size_t size,
				     u64 *actual_size_out)
{
	u32 out[MLX5_ST_SZ_DW(save_vhca_state_out)] = {};
	u32 in[MLX5_ST_SZ_DW(save_vhca_state_in)] = {};
	int err;

	MLX5_SET(save_vhca_state_in, in, opcode, MLX5_CMD_OP_SAVE_VHCA_STATE);
	MLX5_SET(save_vhca_state_in, in, op_mod, 0);
	MLX5_SET(save_vhca_state_in, in, vhca_id, vhca_id);
	MLX5_SET(save_vhca_state_in, in, mkey, mkey);
	MLX5_SET(save_vhca_state_in, in, size, size);
	MLX5_SET(save_vhca_state_in, in, incremental, 0);
	MLX5_SET(save_vhca_state_in, in, set_track, 0);

	err = mlx5_cmd_exec_inout(pf_mdev, save_vhca_state, in, out);
	if (err)
		return err;

	*actual_size_out = MLX5_GET(save_vhca_state_out, out,
				    actual_image_size);
	return 0;
}

/* -------- SAVE_VHCA_STATE: per-fd state buffer -------------------------- */

/*
 * Per-SAVE-fd context, hung off vfmig->save_ctxs. All firmware resources
 * are allocated up front in the ioctl handler and torn down on release()
 * (or by pf_cleanup if the PF is removed first). The fd's sole job is to
 * drain the staging pages, framed as one FW_DATA wire record.
 */
struct mlx5_vfmig_save_ctx {
	struct list_head node;		/* on vfmig->save_ctxs */
	struct mlx5_vfmig_pf *vfmig;	/* holds a kref */
	struct mutex io_lock;		/* serializes concurrent read()s */
	u32 vf_id;
	u16 vhca_id;
	u32 flags;			/* MLX5_VFMIG_SAVE_FLAG_* */

	/*
	 * Transient suspend bookkeeping for the self-suspend / resume-on-
	 * close policy. @owns_suspend is true only when this SAVE session
	 * issued the SUSPEND itself (the VF was RUNNING/P2P at open); it is
	 * false when the caller pre-parked the VF to STOP via SUSPEND_VHCA,
	 * in which case the caller owns the matching RESUME_VHCA and close()
	 * must not auto-resume. The suspended_* bools track which ladder
	 * steps this session actually issued, so close() (or the setup error
	 * path) undoes exactly those.
	 */
	bool owns_suspend;
	bool suspended_initiator;
	bool suspended_responder;

	/* Firmware-tied resources, mutated under vfmig->lock. */
	bool resources_freed;
	bool pd_allocated;
	u32 pdn;
	bool image_dma_mapped;
	bool image_mkey_created;
	struct page **image_pages;
	u32 image_npages;		/* allocated capacity in PAGE_SIZE */
	u32 *image_mkey_in;
	u32 image_mkey;
	struct dma_iova_state image_dma_state;

	/*
	 * Wire prefix (STREAM_HEADER + HOST_PAGE records) snapshotted from
	 * the source VF's vfmig_iova_domain at SAVE-ioctl time into one
	 * contiguous kvmalloc'd buffer, so the read() path stays a simple
	 * byte-cursor walk. NULL / 0 when the source VF was untracked, in
	 * which case the wire stream is just the FW_DATA record.
	 */
	void *host_pages_buf;
	u64 host_pages_size;

	u64 image_size;			/* bytes the firmware wrote */
	u64 read_pos;			/* cursor over [host pages | FW_DATA] */
};

/* Build the on-wire FW_DATA header for ctx->image_size into @hdr. */
static void vfmig_save_build_header(struct mlx5_vfmig_save_ctx *ctx,
				    struct vfmig_wire_header *hdr)
{
	hdr->record_size = cpu_to_le64(ctx->image_size);
	hdr->flags = cpu_to_le32(0);
	hdr->tag = cpu_to_le32(VFMIG_WIRE_TAG_FW_DATA);
}

/* Pass-1 for vfmig_iova_for_each: sum HOST_PAGE footprint + count entries. */
struct vfmig_save_hp_size_ctx {
	u64 total;
	u64 count;
};

static int vfmig_save_hp_count_cb(enum vfmig_iova_slot slot, u64 instance_key,
				  dma_addr_t iova, const void *vaddr,
				  size_t len, void *ctx)
{
	struct vfmig_save_hp_size_ctx *sc = ctx;

	sc->total += sizeof(struct vfmig_wire_header) +
		     sizeof(struct vfmig_host_page_record) + len;
	sc->count++;
	return 0;
}

/*
 * Pass-3 for vfmig_iova_for_each: serialize one HOST_PAGE record (wire
 * header + sub-header + page contents) into @ctx->buf at @ctx->cursor and
 * fold the record's identity tuple into the running manifest CRC. The
 * destination recomputes the same fold and checks it against the value
 * the STREAM_HEADER advertises.
 */
struct vfmig_save_hp_emit_ctx {
	u8 *buf;
	u64 capacity;
	u64 cursor;
	u32 crc;
};

static int vfmig_save_hp_emit_cb(enum vfmig_iova_slot slot, u64 instance_key,
				 dma_addr_t iova, const void *vaddr,
				 size_t len, void *ctx)
{
	struct vfmig_save_hp_emit_ctx *ec = ctx;
	struct vfmig_wire_header hdr;
	struct vfmig_host_page_record sub;
	u64 record_size = sizeof(sub) + len;
	u64 need = sizeof(hdr) + record_size;

	if (ec->cursor + need > ec->capacity)
		return -EOVERFLOW;

	hdr.record_size = cpu_to_le64(record_size);
	hdr.flags	= 0;
	hdr.tag		= cpu_to_le32(VFMIG_WIRE_TAG_HOST_PAGE);
	memcpy(ec->buf + ec->cursor, &hdr, sizeof(hdr));
	ec->cursor += sizeof(hdr);

	sub.slot_id	 = cpu_to_le32(slot);
	sub.flags	 = 0;
	sub.instance_key = cpu_to_le64(instance_key);
	sub.iova	 = cpu_to_le64(iova);
	sub.len		 = cpu_to_le64(len);
	memcpy(ec->buf + ec->cursor, &sub, sizeof(sub));
	ec->cursor += sizeof(sub);

	/*
	 * Fold the on-wire identity tuple into the manifest CRC field by
	 * field (not memcpy(&sub)) so the hash covers exactly the bytes the
	 * destination sees, regardless of any struct padding.
	 */
	ec->crc = crc32_le(ec->crc, (const u8 *)&sub.slot_id,
			   sizeof(sub.slot_id));
	ec->crc = crc32_le(ec->crc, (const u8 *)&sub.flags,
			   sizeof(sub.flags));
	ec->crc = crc32_le(ec->crc, (const u8 *)&sub.instance_key,
			   sizeof(sub.instance_key));
	ec->crc = crc32_le(ec->crc, (const u8 *)&sub.iova,
			   sizeof(sub.iova));
	ec->crc = crc32_le(ec->crc, (const u8 *)&sub.len,
			   sizeof(sub.len));

	memcpy(ec->buf + ec->cursor, vaddr, len);
	ec->cursor += len;
	return 0;
}

/* Pass-2 for vfmig_iova_for_each_external: size + count retagged entries. */
struct vfmig_save_hup_size_ctx {
	u64 total;
	u64 count;
};

static int vfmig_save_hup_count_cb(u8 kind, u64 fw_id, dma_addr_t iova,
				   size_t len, void *ctx)
{
	struct vfmig_save_hup_size_ctx *sc = ctx;

	/*
	 * Un-retagged (auto-numbered) entries have no stable cross-host
	 * identity to emit; skip them. Until the source-side retag
	 * callsites land, every external entry is KIND_NONE, so a tracked
	 * VF counts zero user-page records and the SAVE footprint is
	 * unchanged from the HOST_PAGE-only layout.
	 */
	if (kind == VFMIG_HUOBJ_KIND_NONE)
		return 0;

	sc->total += sizeof(struct vfmig_wire_header) +
		     sizeof(struct vfmig_host_user_page_record);
	sc->count++;
	return 0;
}

/*
 * Pass-4 for vfmig_iova_for_each_external: serialize one identity-only
 * HOST_USER_PAGE record and fold its tuple into the manifest CRC
 * (continued from the HOST_PAGE pass, so the destination folds HP then
 * HUP in the same order). No page contents -- the umem is CRIU's.
 */
struct vfmig_save_hup_emit_ctx {
	u8 *buf;
	u64 capacity;
	u64 cursor;
	u32 crc;
};

static int vfmig_save_hup_emit_cb(u8 kind, u64 fw_id, dma_addr_t iova,
				  size_t len, void *ctx)
{
	struct vfmig_save_hup_emit_ctx *ec = ctx;
	struct vfmig_wire_header hdr;
	struct vfmig_host_user_page_record sub;
	u64 record_size = sizeof(sub);
	u64 need = sizeof(hdr) + record_size;

	if (kind == VFMIG_HUOBJ_KIND_NONE)
		return 0;

	if (ec->cursor + need > ec->capacity)
		return -EOVERFLOW;

	hdr.record_size = cpu_to_le64(record_size);
	hdr.flags	= 0;
	hdr.tag		= cpu_to_le32(VFMIG_WIRE_TAG_HOST_USER_PAGE);
	memcpy(ec->buf + ec->cursor, &hdr, sizeof(hdr));
	ec->cursor += sizeof(hdr);

	sub.flags	 = 0;
	sub.reserved	 = 0;
	sub.instance_key = cpu_to_le64(VFMIG_HUOBJ_KEY(kind, fw_id));
	sub.iova	 = cpu_to_le64(iova);
	sub.len		 = cpu_to_le64(len);
	memcpy(ec->buf + ec->cursor, &sub, sizeof(sub));
	ec->cursor += sizeof(sub);

	/* Field-by-field fold (see vfmig_save_hp_emit_cb) to skip padding. */
	ec->crc = crc32_le(ec->crc, (const u8 *)&sub.flags, sizeof(sub.flags));
	ec->crc = crc32_le(ec->crc, (const u8 *)&sub.reserved,
			   sizeof(sub.reserved));
	ec->crc = crc32_le(ec->crc, (const u8 *)&sub.instance_key,
			   sizeof(sub.instance_key));
	ec->crc = crc32_le(ec->crc, (const u8 *)&sub.iova, sizeof(sub.iova));
	ec->crc = crc32_le(ec->crc, (const u8 *)&sub.len, sizeof(sub.len));
	return 0;
}

static int vfmig_save_kobj_count_cb(u8 kind, u32 key, u32 id, void *ctx)
{
	u64 *total = ctx;

	*total += sizeof(struct vfmig_wire_header) +
		  sizeof(struct vfmig_host_kobj_record);
	return 0;
}

struct vfmig_save_kobj_emit_ctx {
	u8 *buf;
	u64 capacity;
	u64 cursor;
};

static int vfmig_save_kobj_emit_cb(u8 kind, u32 key, u32 id, void *ctx)
{
	struct vfmig_save_kobj_emit_ctx *ec = ctx;
	struct vfmig_host_kobj_record sub = {};
	struct vfmig_wire_header hdr = {};

	if (ec->cursor + sizeof(hdr) + sizeof(sub) > ec->capacity)
		return -EOVERFLOW;

	hdr.record_size = cpu_to_le64(sizeof(sub));
	hdr.tag		= cpu_to_le32(VFMIG_WIRE_TAG_HOST_KOBJ);
	memcpy(ec->buf + ec->cursor, &hdr, sizeof(hdr));
	ec->cursor += sizeof(hdr);

	sub.kind = cpu_to_le32(kind);
	sub.key	 = cpu_to_le32(key);
	sub.id	 = cpu_to_le32(id);
	memcpy(ec->buf + ec->cursor, &sub, sizeof(sub));
	ec->cursor += sizeof(sub);
	return 0;
}

/*
 * Snapshot the source VF's vfmig_iova_domain registry into @ctx's wire
 * prefix (STREAM_HEADER + N HOST_PAGE records). Owned by
 * @ctx->host_pages_buf / @ctx->host_pages_size. The whole prefix is
 * emitted even for a tracked source with zero entries, so the LOAD parser
 * can always rely on STREAM_HEADER being the first record. A NULL @dom
 * (untracked source) leaves both fields zero (FW_DATA-only stream).
 *
 * Safe to walk the registry lock-free-of-mutation because the source VF
 * is SUSPEND_VHCA'd for the whole SAVE.
 */
static int vfmig_save_build_host_pages_buf(struct mlx5_vfmig_save_ctx *ctx,
					   struct vfmig_iova_domain *dom)
{
	struct vfmig_save_hp_size_ctx sc = {};
	struct vfmig_save_hup_size_ctx sc_hup = {};
	struct vfmig_save_hp_emit_ctx ec;
	struct vfmig_save_hup_emit_ctx ec_hup;
	struct vfmig_save_kobj_emit_ctx ec_kobj;
	struct vfmig_wire_header sh_hdr;
	struct vfmig_stream_header sh_payload;
	const u64 sh_total = sizeof(sh_hdr) + sizeof(sh_payload);
	u64 kobj_total = 0;
	u64 buf_total;
	int err;

	if (!dom)
		return 0;

	/* Size the HOST_PAGE, HOST_USER_PAGE and HOST_KOBJ regions. */
	err = vfmig_iova_for_each(dom, vfmig_save_hp_count_cb, &sc);
	if (err)
		return err;
	err = vfmig_iova_for_each_external(dom, vfmig_save_hup_count_cb,
					   &sc_hup);
	if (err)
		return err;
	err = vfmig_iova_kobj_for_each(dom, vfmig_save_kobj_count_cb,
				       &kobj_total);
	if (err)
		return err;

	buf_total = sh_total + sc.total + sc_hup.total + kobj_total;
	ctx->host_pages_buf = kvmalloc(buf_total, GFP_KERNEL);
	if (!ctx->host_pages_buf)
		return -ENOMEM;

	/*
	 * Pass 3: emit HOST_PAGE records into the buffer just after the
	 * stream header, starting the manifest CRC. The STREAM_HEADER that
	 * advertises the CRC is serialized last, once both record passes
	 * have folded their tuples in.
	 */
	ec.buf	    = (u8 *)ctx->host_pages_buf + sh_total;
	ec.capacity = sc.total;
	ec.cursor   = 0;
	ec.crc	    = 0;
	err = vfmig_iova_for_each(dom, vfmig_save_hp_emit_cb, &ec);
	if (err)
		goto err_free;
	if (WARN_ON(ec.cursor != sc.total)) {
		err = -EIO;
		goto err_free;
	}

	/*
	 * Pass 4: emit HOST_USER_PAGE records immediately after the
	 * HOST_PAGE region, continuing the same manifest CRC. sc_hup.count
	 * is 0 until the source-side retag callsites land, in which case
	 * this pass writes nothing and the CRC equals the HOST_PAGE-only
	 * value.
	 */
	ec_hup.buf	= (u8 *)ctx->host_pages_buf + sh_total + sc.total;
	ec_hup.capacity = sc_hup.total;
	ec_hup.cursor	= 0;
	ec_hup.crc	= ec.crc;
	err = vfmig_iova_for_each_external(dom, vfmig_save_hup_emit_cb,
					   &ec_hup);
	if (err)
		goto err_free;
	if (WARN_ON(ec_hup.cursor != sc_hup.total)) {
		err = -EIO;
		goto err_free;
	}

	ec_kobj.buf	 = (u8 *)ctx->host_pages_buf + sh_total + sc.total +
			   sc_hup.total;
	ec_kobj.capacity = kobj_total;
	ec_kobj.cursor	 = 0;
	err = vfmig_iova_kobj_for_each(dom, vfmig_save_kobj_emit_cb, &ec_kobj);
	if (err)
		goto err_free;
	if (WARN_ON(ec_kobj.cursor != kobj_total)) {
		err = -EIO;
		goto err_free;
	}

	sh_hdr.record_size = cpu_to_le64(sizeof(sh_payload));
	sh_hdr.flags	   = 0;
	sh_hdr.tag	   = cpu_to_le32(VFMIG_WIRE_TAG_STREAM_HEADER);
	memcpy(ctx->host_pages_buf, &sh_hdr, sizeof(sh_hdr));

	sh_payload.magic	  = cpu_to_le32(VFMIG_WIRE_MAGIC);
	sh_payload.version	  = cpu_to_le32(VFMIG_STREAM_VERSION);
	sh_payload.num_pages	  = cpu_to_le64(sc.count);
	sh_payload.manifest_crc32 = cpu_to_le32(ec_hup.crc);
	sh_payload.num_user_pages = cpu_to_le32((u32)sc_hup.count);
	memcpy((u8 *)ctx->host_pages_buf + sizeof(sh_hdr),
	       &sh_payload, sizeof(sh_payload));

	ctx->host_pages_size = buf_total;
	return 0;

err_free:
	kvfree(ctx->host_pages_buf);
	ctx->host_pages_buf = NULL;
	return err;
}

/*
 * Copy out the byte range [read_pos, read_pos+count) of the save stream:
 *   [0 .. HDR_SZ)                  FW_DATA wire header
 *   [HDR_SZ .. HDR_SZ+image_size)  firmware payload from image_pages[]
 * EOF is HDR_SZ + image_size. Caller holds vfmig->lock for read AND
 * ctx->io_lock.
 */
static ssize_t vfmig_save_drain(struct mlx5_vfmig_save_ctx *ctx,
				char __user *ubuf, size_t count)
{
	const u64 HP_SZ  = ctx->host_pages_size;
	const u64 HDR_SZ = sizeof(struct vfmig_wire_header);
	const u64 FW_OFF = HP_SZ + HDR_SZ;
	const u64 total  = FW_OFF + ctx->image_size;
	size_t copied = 0;
	ssize_t err = 0;

	if (ctx->read_pos >= total)
		return 0;

	/* STREAM_HEADER + HOST_PAGE prefix (empty for an untracked source). */
	if (ctx->read_pos < HP_SZ && count) {
		u64 hoff = ctx->read_pos;
		size_t want = min_t(size_t, count, HP_SZ - hoff);

		if (copy_to_user(ubuf, (u8 *)ctx->host_pages_buf + hoff, want))
			return -EFAULT;
		ctx->read_pos += want;
		ubuf += want;
		count -= want;
		copied += want;
	}

	/* FW_DATA wire header. */
	if (ctx->read_pos >= HP_SZ && ctx->read_pos < FW_OFF && count) {
		struct vfmig_wire_header hdr;
		u64 hoff = ctx->read_pos - HP_SZ;
		size_t want = min_t(size_t, count, HDR_SZ - hoff);

		vfmig_save_build_header(ctx, &hdr);
		if (copy_to_user(ubuf, ((u8 *)&hdr) + hoff, want))
			return -EFAULT;
		ctx->read_pos += want;
		ubuf += want;
		count -= want;
		copied += want;
	}

	/* FW payload pages. */
	while (count && ctx->read_pos < total) {
		u64 payload_off = ctx->read_pos - FW_OFF;
		u32 page_idx = payload_off >> PAGE_SHIFT;
		size_t page_off = payload_off & (PAGE_SIZE - 1);
		size_t want = min3((size_t)(total - ctx->read_pos), count,
				   PAGE_SIZE - page_off);
		const u8 *from;

		if (page_idx >= ctx->image_npages)
			return copied ? (ssize_t)copied : -EINVAL;

		from = kmap_local_page(ctx->image_pages[page_idx]);
		if (copy_to_user(ubuf, from + page_off, want)) {
			kunmap_local(from);
			err = -EFAULT;
			break;
		}
		kunmap_local(from);
		ctx->read_pos += want;
		ubuf += want;
		count -= want;
		copied += want;
	}

	if (!copied && err)
		return err;
	return copied;
}

static ssize_t vfmig_save_read(struct file *filp, char __user *ubuf,
			       size_t count, loff_t *ppos)
{
	struct mlx5_vfmig_save_ctx *ctx = filp->private_data;
	struct mlx5_vfmig_pf *vfmig = ctx->vfmig;
	ssize_t ret;

	if (!count)
		return 0;

	mutex_lock(&ctx->io_lock);
	down_read(&vfmig->lock);
	if (vfmig->dead || ctx->resources_freed) {
		ret = -ENODEV;
		goto out;
	}
	ret = vfmig_save_drain(ctx, ubuf, count);
out:
	up_read(&vfmig->lock);
	mutex_unlock(&ctx->io_lock);
	return ret;	/* stream_open() => ppos is NULL, leave it */
}

/*
 * Drop the firmware-tied resources held by @ctx. Idempotent via
 * @resources_freed. Called from release() (pf_mdev alive) or pf_cleanup()
 * (before pf_mdev is NULLed). The image page list is host memory and is
 * freed separately in release(). Caller holds vfmig->lock.
 */
static void vfmig_save_release_resources(struct mlx5_vfmig_save_ctx *ctx)
{
	struct mlx5_core_dev *pf_mdev = ctx->vfmig->pf_mdev;

	if (ctx->resources_freed)
		return;
	ctx->resources_freed = true;

	if (!pf_mdev)
		return;

	if (ctx->image_mkey_created) {
		mlx5_core_destroy_mkey(pf_mdev, ctx->image_mkey);
		ctx->image_mkey_created = false;
	}
	if (ctx->image_dma_mapped) {
		vfmig_unregister_dma_pages(pf_mdev, ctx->image_npages,
					   ctx->image_mkey_in,
					   &ctx->image_dma_state,
					   DMA_FROM_DEVICE);
		ctx->image_dma_mapped = false;
	}
	kvfree(ctx->image_mkey_in);
	ctx->image_mkey_in = NULL;

	if (ctx->pd_allocated) {
		mlx5_core_dealloc_pd(pf_mdev, ctx->pdn);
		ctx->pd_allocated = false;
	}

	/*
	 * Resume-on-close, inverse order of suspend (responder then
	 * initiator). Only undo suspends this session owns and issued, and
	 * only when the caller did not ask to keep the VF parked
	 * (KEEP_SUSPENDED). Best-effort: a failed resume is logged, not
	 * propagated -- the blob is already drained. The suspended_* bools
	 * guard against a stray RESUME if the SUSPEND never landed.
	 */
	if (!ctx->owns_suspend)
		return;
	if (ctx->flags & MLX5_VFMIG_SAVE_FLAG_KEEP_SUSPENDED)
		return;

	if (ctx->suspended_responder) {
		vfmig_dp_resume_step(pf_mdev, ctx->vhca_id, MLX5_VFMIG_DP_STOP);
		ctx->suspended_responder = false;
	}
	if (ctx->suspended_initiator) {
		vfmig_dp_resume_step(pf_mdev, ctx->vhca_id, MLX5_VFMIG_DP_P2P);
		ctx->suspended_initiator = false;
	}
}

static int vfmig_save_release(struct inode *inode, struct file *filp)
{
	struct mlx5_vfmig_save_ctx *ctx = filp->private_data;
	struct mlx5_vfmig_pf *vfmig = ctx->vfmig;

	down_read(&vfmig->lock);
	if (!vfmig->dead)
		vfmig_save_release_resources(ctx);
	up_read(&vfmig->lock);

	mutex_lock(&vfmig->ctxs_lock);
	list_del(&ctx->node);
	mutex_unlock(&vfmig->ctxs_lock);

	kvfree(ctx->host_pages_buf);
	vfmig_free_pages(ctx->image_pages, ctx->image_npages);
	mutex_destroy(&ctx->io_lock);
	vfmig_pf_put(vfmig);
	kfree(ctx);
	return 0;
}

static const struct file_operations mlx5_vfmig_save_fops = {
	.owner		= THIS_MODULE,
	.read		= vfmig_save_read,
	.release	= vfmig_save_release,
};

static bool vfmig_vf_id_load_busy_locked(struct mlx5_vfmig_pf *vfmig,
					 u32 vf_id);

/* True iff @vf_id already has an open SAVE session. ctxs_lock held. */
static bool vfmig_vf_id_save_busy_locked(struct mlx5_vfmig_pf *vfmig, u32 vf_id)
{
	struct mlx5_vfmig_save_ctx *s;

	list_for_each_entry(s, &vfmig->save_ctxs, node)
		if (s->vf_id == vf_id)
			return true;
	return false;
}

/*
 * True iff @vf_id has any open SAVE or LOAD session. SAVE and LOAD are
 * mutually exclusive per VF so a session claims the vf_id for its whole
 * lifetime. ctxs_lock held.
 */
static bool vfmig_vf_id_busy_locked(struct mlx5_vfmig_pf *vfmig, u32 vf_id)
{
	return vfmig_vf_id_save_busy_locked(vfmig, vf_id) ||
	       vfmig_vf_id_load_busy_locked(vfmig, vf_id);
}

/*
 * Set up a SAVE session: resolve vhca_id, quiesce the VF to STOP (owning
 * and later undoing only the ladder steps this session issues), size the
 * snapshot, allocate a PD + image pages + MKEY, run SAVE_VHCA_STATE, then
 * hand back a read-only anon-inode fd. Caller holds vfmig->lock for read.
 */
static long vfmig_ioc_save_vhca_state(struct mlx5_vfmig_pf *vfmig,
				      void __user *uarg)
{
	struct mlx5_core_dev *pf_mdev = vfmig->pf_mdev;
	struct mlx5_vfmig_save_state arg;
	struct mlx5_vfmig_save_ctx *ctx;
	struct mlx5_core_sriov *sriov;
	bool migratable = false;
	u64 query_size = 0;
	u64 actual_size = 0;
	struct file *file;
	u32 npages;
	u16 vhca_id;
	int fd, err;

	if (copy_from_user(&arg, uarg, sizeof(arg)))
		return -EFAULT;
	if (arg.reserved || (arg.flags & ~MLX5_VFMIG_SAVE_FLAG_ALL))
		return -EINVAL;

	sriov = &pf_mdev->priv.sriov;
	if (arg.vf_id >= sriov->num_vfs)
		return -EINVAL;

	err = vfmig_check_pf_migration_caps(pf_mdev);
	if (err)
		return err;

	err = vfmig_query_vf_migratable(pf_mdev, arg.vf_id, &migratable);
	if (err)
		return err;
	if (!migratable) {
		mlx5_core_warn(pf_mdev,
			       "vfmig: vf %u is not migration-enabled\n",
			       arg.vf_id);
		return -EOPNOTSUPP;
	}

	err = vfmig_query_vhca_id(pf_mdev, arg.vf_id + 1, &vhca_id);
	if (err)
		return err;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	INIT_LIST_HEAD(&ctx->node);
	mutex_init(&ctx->io_lock);
	ctx->vf_id = arg.vf_id;
	ctx->vhca_id = vhca_id;
	ctx->flags = arg.flags;

	/* Claim vf_id atomically vs other SAVE/LOAD sessions. */
	mutex_lock(&vfmig->ctxs_lock);
	if (vfmig_vf_id_busy_locked(vfmig, ctx->vf_id)) {
		mutex_unlock(&vfmig->ctxs_lock);
		err = -EBUSY;
		goto err_claim;
	}
	vfmig_pf_get(vfmig);
	ctx->vfmig = vfmig;
	list_add(&ctx->node, &vfmig->save_ctxs);
	mutex_unlock(&vfmig->ctxs_lock);

	err = mlx5_core_alloc_pd(pf_mdev, &ctx->pdn);
	if (err)
		goto err_res;
	ctx->pd_allocated = true;

	/*
	 * Quiesce to STOP for the capture, owning only the steps we issue:
	 *   - STOP already (explicit SUSPEND_VHCA): do nothing; the caller
	 *     owns the resume via RESUME_VHCA.
	 *   - P2P (explicit SUSPEND_VHCA(INITIATOR)): suspend the responder
	 *     only, and resume just that on close.
	 *   - RUNNING (standalone SAVE): suspend both directions and resume
	 *     both on close.
	 * The persistent vfmig_dp_state is owned by SUSPEND/RESUME_VHCA and
	 * left untouched: SAVE's suspend is transient and undone on close.
	 */
	switch (sriov->vfs_ctx[arg.vf_id].vfmig_dp_state) {
	case MLX5_VFMIG_DP_STOP:
		ctx->owns_suspend = false;
		break;
	case MLX5_VFMIG_DP_P2P:
		ctx->owns_suspend = true;
		err = vfmig_dp_suspend_step(pf_mdev, vhca_id,
					    MLX5_VFMIG_DP_P2P);
		if (err)
			goto err_res;
		ctx->suspended_responder = true;
		break;
	default: /* MLX5_VFMIG_DP_RUNNING */
		ctx->owns_suspend = true;
		err = vfmig_dp_suspend_step(pf_mdev, vhca_id,
					    MLX5_VFMIG_DP_RUNNING);
		if (err)
			goto err_res;
		ctx->suspended_initiator = true;
		err = vfmig_dp_suspend_step(pf_mdev, vhca_id,
					    MLX5_VFMIG_DP_P2P);
		if (err)
			goto err_res;
		ctx->suspended_responder = true;
		break;
	}

	err = vfmig_cmd_query_vhca_migration_state(pf_mdev, vhca_id,
						   &query_size);
	if (err) {
		mlx5_core_warn(pf_mdev,
			       "vfmig: QUERY_VHCA_MIGRATION_STATE vf %u (vhca_id 0x%04x) failed: %d\n",
			       arg.vf_id, vhca_id, err);
		goto err_res;
	}
	if (!query_size || query_size > VFMIG_MAX_SAVE_SIZE) {
		mlx5_core_warn(pf_mdev,
			       "vfmig: implausible migration size %llu for vf %u\n",
			       query_size, arg.vf_id);
		err = -ERANGE;
		goto err_res;
	}

	npages = max_t(u32, 1, DIV_ROUND_UP(query_size, PAGE_SIZE));
	err = vfmig_alloc_pages(&ctx->image_pages, npages);
	if (err)
		goto err_res;
	ctx->image_npages = npages;

	ctx->image_mkey_in = vfmig_alloc_mkey_in(npages, ctx->pdn);
	if (!ctx->image_mkey_in) {
		err = -ENOMEM;
		goto err_res;
	}

	err = vfmig_register_dma_pages(pf_mdev, npages, ctx->image_pages,
				       ctx->image_mkey_in,
				       &ctx->image_dma_state,
				       DMA_FROM_DEVICE);
	if (err)
		goto err_res;
	ctx->image_dma_mapped = true;

	err = vfmig_create_mkey(pf_mdev, npages, ctx->image_mkey_in,
				&ctx->image_mkey);
	if (err)
		goto err_res;
	ctx->image_mkey_created = true;

	err = vfmig_cmd_save_vhca_state(pf_mdev, vhca_id, ctx->image_mkey,
					npages * PAGE_SIZE, &actual_size);
	if (err) {
		mlx5_core_warn(pf_mdev,
			       "vfmig: SAVE_VHCA_STATE vf %u (vhca_id 0x%04x) failed: %d\n",
			       arg.vf_id, vhca_id, err);
		goto err_res;
	}
	if (!actual_size || actual_size > (u64)npages * PAGE_SIZE) {
		mlx5_core_warn(pf_mdev,
			       "vfmig: SAVE_VHCA_STATE returned implausible size %llu for vf %u\n",
			       actual_size, arg.vf_id);
		err = -EIO;
		goto err_res;
	}
	ctx->image_size = actual_size;

	/*
	 * If the source VF is tracked, snapshot its deterministic-IOVA
	 * domain into the STREAM_HEADER + HOST_PAGE wire prefix now, while
	 * the VHCA is suspended (so the registry is stable). An untracked
	 * source leaves host_pages_size == 0 and the stream is FW_DATA-only.
	 */
	mutex_lock(&vfmig->ctxs_lock);
	err = vfmig_save_build_host_pages_buf(ctx,
					      vfmig->iova_dom[arg.vf_id]);
	mutex_unlock(&vfmig->ctxs_lock);
	if (err) {
		mlx5_core_warn(pf_mdev,
			       "vfmig: vf %u: building HOST_PAGE prefix failed: %d\n",
			       arg.vf_id, err);
		goto err_res;
	}

	fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd < 0) {
		err = fd;
		goto err_res;
	}

	file = anon_inode_getfile("mlx5_vfmig_save", &mlx5_vfmig_save_fops,
				  ctx, O_RDONLY | O_CLOEXEC);
	if (IS_ERR(file)) {
		err = PTR_ERR(file);
		goto err_fd;
	}
	stream_open(file_inode(file), file);

	arg.save_fd = fd;
	if (copy_to_user(uarg, &arg, sizeof(arg))) {
		err = -EFAULT;
		goto err_file;
	}

	fd_install(fd, file);
	//mlx5_core_info(pf_mdev,
	//	       "vfmig: saved vf %u (vhca_id 0x%04x) state: %llu bytes\n",
	//	       arg.vf_id, vhca_id, actual_size);
	return 0;

err_file:
	/* fput() runs vfmig_save_release, which frees resources + ctx. */
	fput(file);
	put_unused_fd(fd);
	return err;
err_fd:
	put_unused_fd(fd);
err_res:
	/*
	 * Setup failed and no fd escapes, so fully restore the VF: drop
	 * KEEP_SUSPENDED before teardown so release_resources unwinds any
	 * suspend this session issued, even if the caller asked to keep it
	 * parked on a *successful* save.
	 */
	ctx->flags &= ~MLX5_VFMIG_SAVE_FLAG_KEEP_SUSPENDED;
	vfmig_save_release_resources(ctx);
	kvfree(ctx->host_pages_buf);
	vfmig_free_pages(ctx->image_pages, ctx->image_npages);
	mutex_lock(&vfmig->ctxs_lock);
	list_del(&ctx->node);
	mutex_unlock(&vfmig->ctxs_lock);
	vfmig_pf_put(vfmig);
	mutex_destroy(&ctx->io_lock);
	kfree(ctx);
	return err;
err_claim:
	mutex_destroy(&ctx->io_lock);
	kfree(ctx);
	return err;
}

/* -------- LOAD_VHCA_STATE: per-fd state buffer ------------------------- */

/*
 * Synchronous LOAD_VHCA_STATE. @size is the payload byte count the
 * firmware should ingest from the MTT-mapped @mkey.
 */
static int vfmig_cmd_load_vhca_state(struct mlx5_core_dev *pf_mdev,
				     u16 vhca_id, u32 mkey, size_t size)
{
	u32 out[MLX5_ST_SZ_DW(load_vhca_state_out)] = {};
	u32 in[MLX5_ST_SZ_DW(load_vhca_state_in)] = {};

	MLX5_SET(load_vhca_state_in, in, opcode, MLX5_CMD_OP_LOAD_VHCA_STATE);
	MLX5_SET(load_vhca_state_in, in, op_mod, 0);
	MLX5_SET(load_vhca_state_in, in, vhca_id, vhca_id);
	MLX5_SET(load_vhca_state_in, in, mkey, mkey);
	MLX5_SET(load_vhca_state_in, in, size, size);

	return mlx5_cmd_exec_inout(pf_mdev, load_vhca_state, in, out);
}

/* Parser states for the write() FSM. */
enum vfmig_load_state {
	VFMIG_LS_READ_HEADER = 0,	/* accumulating the 16-byte header */
	VFMIG_LS_STREAM_HDR_READ,	/* reading the 24-byte stream header */
	VFMIG_LS_HP_READ_SUBHDR,	/* reading a HOST_PAGE sub-header */
	VFMIG_LS_HP_READ_DATA,		/* reading a HOST_PAGE's page contents */
	VFMIG_LS_HP_REPLAY,		/* replaying the HOST_PAGE into the domain */
	VFMIG_LS_HUP_READ_SUBHDR,	/* reading a HOST_USER_PAGE sub-header */
	VFMIG_LS_HUP_REPLAY,		/* replaying the HOST_USER_PAGE placeholder */
	VFMIG_LS_KOBJ_READ,		/* reading + replaying a HOST_KOBJ record */
	VFMIG_LS_PREP_IMAGE,		/* allocate staging for the payload */
	VFMIG_LS_READ_IMAGE,		/* accumulating the FW_DATA payload */
	VFMIG_LS_LOAD_IMAGE,		/* payload complete, run LOAD */
	VFMIG_LS_DONE,			/* loaded; reject trailing bytes */
};

/*
 * Per-LOAD-fd context, hung off vfmig->load_ctxs. Mirrors the SAVE ctx
 * but in the write direction (DMA_TO_DEVICE): the write() FSM ingests one
 * FW_DATA record and stages it into DMA pages + an MTT MKEY. The
 * LOAD_VHCA_STATE firmware command does NOT run here -- at LOAD-ioctl
 * time the destination VHCA has not been re-enabled by a probe yet, so
 * the command would be a no-op. Instead, once the payload is complete
 * the resources are transferred, on fd close, into the PF's per-VF
 * pending_load slot, where the VF's next mlx5_core probe applies them.
 */
struct mlx5_vfmig_load_ctx {
	struct list_head node;		/* on vfmig->load_ctxs */
	struct mlx5_vfmig_pf *vfmig;	/* holds a kref */
	struct mutex io_lock;		/* serializes concurrent write()s */
	u32 vf_id;
	u16 vhca_id;

	enum vfmig_load_state state;
	u8 hdr_buf[sizeof(struct vfmig_wire_header)];
	u32 hdr_filled;			/* header bytes accumulated */
	u64 record_size;		/* current record's payload size */
	u64 image_filled;		/* payload bytes staged so far */
	bool image_staged;		/* complete blob staged, ready to hand off */
	bool image_transferred;		/* resources moved into pending_load slot */

	/*
	 * Destination VF's deterministic IOVA domain, captured from
	 * vfmig->iova_dom[vf_id] at LOAD-ioctl time. NULL iff the
	 * destination was not SET_TRACKED'd before LOAD; a HOST_PAGE-bearing
	 * blob against a NULL domain is a userspace ordering bug and is
	 * rejected by the parser. The SET_TRACKED{enable=0}/sriov_disable/
	 * pf_unbind teardown paths all require the VF unbound, and LOAD is
	 * only useful while the VF is unbound, so the captured pointer stays
	 * live for the fd's lifetime.
	 */
	struct vfmig_iova_domain *iova_dom;

	/*
	 * Stream-header bookkeeping. The very first record of any vfmig blob
	 * MUST be a STREAM_HEADER; it pins @hp_expected (num_pages) and
	 * @manifest_crc_want. @manifest_crc_have accumulates the per-record
	 * identity fold and is checked once @hp_seen == @hp_expected.
	 */
	bool stream_hdr_seen;
	u8   stream_hdr_buf[sizeof(struct vfmig_stream_header)];
	u32  stream_hdr_filled;
	u64  hp_expected;
	u64  hp_seen;
	u32  manifest_crc_want;
	u32  manifest_crc_have;
	bool records_finalized;		/* CRC verified + drift armed (once) */
	bool cursor_reset_done;		/* reset_cursor called at release (once) */

	/*
	 * Per-HOST_PAGE-record scratch (valid only in the VFMIG_LS_HP_*
	 * states). @hp_contents is kvmalloc'd in HP_READ_SUBHDR, filled in
	 * HP_READ_DATA, consumed + freed in HP_REPLAY (and unconditionally
	 * on fd close, to handle a partial mid-record close).
	 */
	u8  hp_subhdr_buf[sizeof(struct vfmig_host_page_record)];
	u32 hp_subhdr_filled;
	enum vfmig_iova_slot hp_slot;
	u64 hp_instance_key;
	u64 hp_iova;
	u64 hp_len;
	void *hp_contents;
	u64 hp_filled;

	/*
	 * HOST_USER_PAGE accounting + per-record scratch. @hup_expected is
	 * pinned from the stream header's num_user_pages; @hup_seen counts
	 * placeholders replayed so far. The identity-only sub-header (no
	 * page contents follow) is accumulated into @hup_subhdr_buf in
	 * VFMIG_LS_HUP_READ_SUBHDR and consumed in VFMIG_LS_HUP_REPLAY.
	 */
	u64 hup_expected;
	u64 hup_seen;
	u8  hup_subhdr_buf[sizeof(struct vfmig_host_user_page_record)];
	u32 hup_subhdr_filled;
	u64 hup_instance_key;
	u64 hup_iova;
	u64 hup_len;

	/* HOST_KOBJ record being read (VFMIG_LS_KOBJ_READ). */
	u8  kobj_buf[sizeof(struct vfmig_host_kobj_record)];
	u32 kobj_filled;

	/* Firmware-tied resources, mutated under vfmig->lock. */
	bool resources_freed;
	bool pd_allocated;
	u32 pdn;
	bool image_dma_mapped;
	bool image_mkey_created;
	struct page **image_pages;
	u32 image_npages;
	u32 *image_mkey_in;
	u32 image_mkey;
	struct dma_iova_state image_dma_state;
};

/* True iff @vf_id already has an open LOAD session. ctxs_lock held. */
static bool vfmig_vf_id_load_busy_locked(struct mlx5_vfmig_pf *vfmig,
					 u32 vf_id)
{
	struct mlx5_vfmig_load_ctx *l;

	list_for_each_entry(l, &vfmig->load_ctxs, node)
		if (l->vf_id == vf_id)
			return true;
	return false;
}

/* Accumulate up to @want header bytes; returns bytes taken or -EFAULT. */
static ssize_t vfmig_load_consume_header(struct mlx5_vfmig_load_ctx *ctx,
					 const char __user *ubuf, size_t want)
{
	size_t need = sizeof(ctx->hdr_buf) - ctx->hdr_filled;
	size_t take = min(need, want);

	if (!take)
		return 0;
	if (copy_from_user(ctx->hdr_buf + ctx->hdr_filled, ubuf, take))
		return -EFAULT;
	ctx->hdr_filled += take;
	return take;
}

/* Copy @want payload bytes from user into the staging pages at image_filled. */
static ssize_t vfmig_load_consume_image(struct mlx5_vfmig_load_ctx *ctx,
					const char __user *ubuf, size_t want)
{
	size_t copied = 0;

	while (want) {
		size_t page_off = ctx->image_filled & (PAGE_SIZE - 1);
		u32 page_idx = ctx->image_filled >> PAGE_SHIFT;
		size_t chunk = min_t(size_t, want, PAGE_SIZE - page_off);
		u8 *to;

		if (page_idx >= ctx->image_npages)
			return copied ? (ssize_t)copied : -EINVAL;

		to = kmap_local_page(ctx->image_pages[page_idx]);
		if (copy_from_user(to + page_off, ubuf, chunk)) {
			kunmap_local(to);
			return copied ? (ssize_t)copied : -EFAULT;
		}
		kunmap_local(to);

		ctx->image_filled += chunk;
		ubuf += chunk;
		want -= chunk;
		copied += chunk;
	}
	return copied;
}

/*
 * Allocate the staging buffer (@want_npages pages) + MTT MKEY the firmware
 * will read for LOAD_VHCA_STATE. The PD was allocated in the ioctl handler.
 * Caller holds vfmig->lock for read.
 */
static int vfmig_load_prepare_image(struct mlx5_vfmig_load_ctx *ctx,
				    u32 want_npages)
{
	struct mlx5_core_dev *pf_mdev = ctx->vfmig->pf_mdev;
	int err;

	if (WARN_ON(!pf_mdev))
		return -ENODEV;

	err = vfmig_alloc_pages(&ctx->image_pages, want_npages);
	if (err)
		return err;
	ctx->image_npages = want_npages;

	ctx->image_mkey_in = vfmig_alloc_mkey_in(want_npages, ctx->pdn);
	if (!ctx->image_mkey_in) {
		err = -ENOMEM;
		goto err_pages;
	}

	err = vfmig_register_dma_pages(pf_mdev, want_npages, ctx->image_pages,
				       ctx->image_mkey_in,
				       &ctx->image_dma_state, DMA_TO_DEVICE);
	if (err)
		goto err_mkey_in;
	ctx->image_dma_mapped = true;

	err = vfmig_create_mkey(pf_mdev, want_npages, ctx->image_mkey_in,
				&ctx->image_mkey);
	if (err)
		goto err_dma;
	ctx->image_mkey_created = true;
	return 0;

err_dma:
	vfmig_unregister_dma_pages(pf_mdev, want_npages, ctx->image_mkey_in,
				   &ctx->image_dma_state, DMA_TO_DEVICE);
	ctx->image_dma_mapped = false;
err_mkey_in:
	kvfree(ctx->image_mkey_in);
	ctx->image_mkey_in = NULL;
err_pages:
	vfmig_free_pages(ctx->image_pages, ctx->image_npages);
	ctx->image_pages = NULL;
	ctx->image_npages = 0;
	return err;
}

/*
 * Once every HOST_PAGE and HOST_USER_PAGE record the STREAM_HEADER
 * promised has been replayed, verify the running manifest CRC matches
 * what the source pinned and arm at-probe drift detection. Latched by
 * @records_finalized; a no-op until both hp_seen == hp_expected and
 * hup_seen == hup_expected (the CRC folds HOST_PAGE then HOST_USER_PAGE
 * records, so it is only complete once both streams are drained).
 */
static int vfmig_load_maybe_finalize_records(struct mlx5_vfmig_load_ctx *ctx)
{
	if (ctx->records_finalized)
		return 0;
	if (ctx->hp_seen != ctx->hp_expected ||
	    ctx->hup_seen != ctx->hup_expected)
		return 0;

	if (ctx->manifest_crc_have != ctx->manifest_crc_want) {
		mlx5_core_warn(ctx->vfmig->pf_mdev,
			       "vfmig: vf %u: manifest CRC mismatch (have 0x%08x, want 0x%08x); HOST_PAGE identity stream corrupted\n",
			       ctx->vf_id, ctx->manifest_crc_have,
			       ctx->manifest_crc_want);
		return -EPROTO;
	}
	vfmig_iova_arm_drift_detection(ctx->iova_dom);
	ctx->records_finalized = true;
	return 0;
}

/*
 * Validate the parsed 16-byte wire header and dispatch to the record's
 * body reader. The first record of a blob must be a STREAM_HEADER;
 * thereafter HOST_PAGE records (if any) precede a single terminating
 * FW_DATA record.
 */
static int vfmig_load_dispatch_header(struct mlx5_vfmig_load_ctx *ctx)
{
	struct vfmig_wire_header *hdr =
		(struct vfmig_wire_header *)ctx->hdr_buf;
	u64 record_size = le64_to_cpu(hdr->record_size);
	u32 flags = le32_to_cpu(hdr->flags);
	u32 tag = le32_to_cpu(hdr->tag);

	if (flags) {
		mlx5_core_warn(ctx->vfmig->pf_mdev,
			       "vfmig: vf %u: LOAD record tag 0x%x sets reserved flags 0x%x\n",
			       ctx->vf_id, tag, flags);
		return -EOPNOTSUPP;
	}
	if (record_size > VFMIG_MAX_SAVE_SIZE)
		return -EINVAL;

	ctx->record_size = record_size;
	ctx->hdr_filled = 0;

	/*
	 * A tracked source always leads with a STREAM_HEADER (then its
	 * HOST_PAGE records, then FW_DATA). A legacy / untracked source
	 * emits a bare FW_DATA record with no prefix: accept that too so
	 * untracked save/load round-trips keep working. A HOST_PAGE record
	 * without a preceding STREAM_HEADER falls through to hp_expected==0
	 * and is rejected below as "beyond declared num_pages".
	 */
	switch (tag) {
	case VFMIG_WIRE_TAG_STREAM_HEADER:
		if (ctx->stream_hdr_seen) {
			mlx5_core_warn(ctx->vfmig->pf_mdev,
				       "vfmig: vf %u: duplicate STREAM_HEADER\n",
				       ctx->vf_id);
			return -EPROTO;
		}
		if (record_size != sizeof(struct vfmig_stream_header))
			return -EPROTO;
		ctx->stream_hdr_filled = 0;
		ctx->state = VFMIG_LS_STREAM_HDR_READ;
		return 0;
	case VFMIG_WIRE_TAG_HOST_PAGE:
		if (!ctx->iova_dom) {
			mlx5_core_warn(ctx->vfmig->pf_mdev,
				       "vfmig: vf %u: HOST_PAGE record but destination not SET_TRACKED'd; aborting LOAD\n",
				       ctx->vf_id);
			return -EINVAL;
		}
		if (record_size < sizeof(struct vfmig_host_page_record))
			return -EINVAL;
		if (ctx->hp_seen >= ctx->hp_expected) {
			mlx5_core_warn(ctx->vfmig->pf_mdev,
				       "vfmig: vf %u: HOST_PAGE record beyond declared num_pages=%llu\n",
				       ctx->vf_id,
				       (unsigned long long)ctx->hp_expected);
			return -EPROTO;
		}
		ctx->hp_subhdr_filled = 0;
		ctx->hp_filled = 0;
		ctx->state = VFMIG_LS_HP_READ_SUBHDR;
		return 0;
	case VFMIG_WIRE_TAG_HOST_USER_PAGE:
		if (!ctx->iova_dom) {
			mlx5_core_warn(ctx->vfmig->pf_mdev,
				       "vfmig: vf %u: HOST_USER_PAGE record but destination not SET_TRACKED'd; aborting LOAD\n",
				       ctx->vf_id);
			return -EINVAL;
		}
		if (record_size != sizeof(struct vfmig_host_user_page_record))
			return -EINVAL;
		if (ctx->hup_seen >= ctx->hup_expected) {
			mlx5_core_warn(ctx->vfmig->pf_mdev,
				       "vfmig: vf %u: HOST_USER_PAGE record beyond declared num_user_pages=%llu\n",
				       ctx->vf_id,
				       (unsigned long long)ctx->hup_expected);
			return -EPROTO;
		}
		ctx->hup_subhdr_filled = 0;
		ctx->state = VFMIG_LS_HUP_READ_SUBHDR;
		return 0;
	case VFMIG_WIRE_TAG_HOST_KOBJ:
		if (!ctx->iova_dom || !ctx->records_finalized) {
			mlx5_core_warn(ctx->vfmig->pf_mdev,
				       "vfmig: vf %u: HOST_KOBJ record %s; aborting LOAD\n",
				       ctx->vf_id, !ctx->iova_dom ?
				       "but destination not SET_TRACKED'd" :
				       "before the HOST_PAGE records");
			return -EPROTO;
		}
		if (record_size != sizeof(struct vfmig_host_kobj_record))
			return -EINVAL;
		ctx->kobj_filled = 0;
		ctx->state = VFMIG_LS_KOBJ_READ;
		return 0;
	case VFMIG_WIRE_TAG_FW_DATA:
		if (ctx->image_staged) {
			mlx5_core_warn(ctx->vfmig->pf_mdev,
				       "vfmig: vf %u: multiple FW_DATA records per LOAD session not supported\n",
				       ctx->vf_id);
			return -EINVAL;
		}
		if (ctx->hp_seen != ctx->hp_expected) {
			mlx5_core_warn(ctx->vfmig->pf_mdev,
				       "vfmig: vf %u: FW_DATA before all HOST_PAGE records (%llu / %llu); aborting\n",
				       ctx->vf_id,
				       (unsigned long long)ctx->hp_seen,
				       (unsigned long long)ctx->hp_expected);
			return -EPROTO;
		}
		if (ctx->hup_seen != ctx->hup_expected) {
			mlx5_core_warn(ctx->vfmig->pf_mdev,
				       "vfmig: vf %u: FW_DATA before all HOST_USER_PAGE records (%llu / %llu); aborting\n",
				       ctx->vf_id,
				       (unsigned long long)ctx->hup_seen,
				       (unsigned long long)ctx->hup_expected);
			return -EPROTO;
		}
		if (!record_size)
			return -EINVAL;
		ctx->image_filled = 0;
		ctx->state = VFMIG_LS_PREP_IMAGE;
		return 0;
	default:
		mlx5_core_warn(ctx->vfmig->pf_mdev,
			       "vfmig: vf %u: unsupported LOAD record tag 0x%x\n",
			       ctx->vf_id, tag);
		return -EOPNOTSUPP;
	}
}

/*
 * Free a per-VF pending_load slot's firmware-tied resources plus its
 * backing pages. @pf_mdev MUST be alive (the FW commands need a working
 * cmd ring); callers guarantee this via vfmig->lock / the vfmig kref.
 */
static void vfmig_vf_load_destroy(struct mlx5_core_dev *pf_mdev,
				  struct mlx5_vfmig_vf_load *load)
{
	if (!load)
		return;

	if (load->mkey_created)
		mlx5_core_destroy_mkey(pf_mdev, load->mkey);
	if (load->dma_mapped)
		vfmig_unregister_dma_pages(pf_mdev, load->npages,
					   load->mkey_in, &load->dma_state,
					   DMA_TO_DEVICE);
	kvfree(load->mkey_in);
	if (load->pd_allocated)
		mlx5_core_dealloc_pd(pf_mdev, load->pdn);
	vfmig_free_pages(load->pages, load->npages);
	kfree(load);
}

/*
 * Install @load into the per-VF slot at pending_load[vf_id] and set the
 * restored latch so the next probe both applies the LOAD and skips
 * INIT_HCA. Returns -EBUSY if a slot is already staged for this VF (the
 * caller then still owns @load). Caller holds vfmig->ctxs_lock.
 */
static int vfmig_install_pending_load_locked(struct mlx5_vfmig_pf *vfmig,
					     struct mlx5_vfmig_vf_load *load)
{
	if (load->vf_id >= vfmig->max_vfs)
		return -EINVAL;
	if (vfmig->pending_load[load->vf_id])
		return -EBUSY;

	vfmig->pending_load[load->vf_id] = load;
	set_bit(load->vf_id, vfmig->restored);
	return 0;
}

/*
 * Mark the completed blob as staged. Does NOT issue LOAD_VHCA_STATE: the
 * destination VHCA has not been re-enabled by a probe yet, so the command
 * would be a no-op. release() hands the staged resources to the per-VF
 * pending_load slot, from where the VF's next mlx5_core probe applies
 * them. Exactly one FW_DATA record is supported; reject a second.
 */
static int vfmig_load_run_load(struct mlx5_vfmig_load_ctx *ctx)
{
	struct mlx5_core_dev *pf_mdev = ctx->vfmig->pf_mdev;

	if (WARN_ON(!ctx->image_mkey_created))
		return -EINVAL;
	if (ctx->image_staged) {
		mlx5_core_warn(pf_mdev,
			       "vfmig: vf %u (vhca_id 0x%04x): multiple FW_DATA records per LOAD session not supported\n",
			       ctx->vf_id, ctx->vhca_id);
		return -EINVAL;
	}

	ctx->image_staged = true;
	ctx->state = VFMIG_LS_DONE;
	mlx5_core_dbg(pf_mdev,
		      "vfmig: staged vf %u (vhca_id 0x%04x) state: %llu bytes; applies on next probe\n",
		      ctx->vf_id, ctx->vhca_id, ctx->record_size);
	return 0;
}

/*
 * Advance the parser one step, consuming from [*ubuf, *ubuf+*left). Some
 * transitions consume zero bytes but are mandatory work, so the caller
 * loops on @progressed rather than on @left.
 */
static int vfmig_load_step(struct mlx5_vfmig_load_ctx *ctx,
			   const char __user **ubuf, size_t *left,
			   bool *progressed)
{
	u32 want_npages;
	ssize_t n;
	int err;

	switch (ctx->state) {
	case VFMIG_LS_READ_HEADER:
		n = vfmig_load_consume_header(ctx, *ubuf, *left);
		if (n < 0)
			return n;
		*ubuf += n;
		*left -= n;
		*progressed = n > 0;
		if (ctx->hdr_filled == sizeof(ctx->hdr_buf))
			return vfmig_load_dispatch_header(ctx);
		return 0;
	case VFMIG_LS_STREAM_HDR_READ: {
		size_t need = sizeof(ctx->stream_hdr_buf) -
			      ctx->stream_hdr_filled;
		size_t take = min(need, *left);
		struct vfmig_stream_header sh;

		if (take) {
			if (copy_from_user(ctx->stream_hdr_buf +
						   ctx->stream_hdr_filled,
					   *ubuf, take))
				return -EFAULT;
			ctx->stream_hdr_filled += take;
			*ubuf += take;
			*left -= take;
			*progressed = true;
		}
		if (ctx->stream_hdr_filled < sizeof(ctx->stream_hdr_buf))
			return 0;

		memcpy(&sh, ctx->stream_hdr_buf, sizeof(sh));
		if (le32_to_cpu(sh.magic) != VFMIG_WIRE_MAGIC) {
			mlx5_core_warn(ctx->vfmig->pf_mdev,
				       "vfmig: vf %u: stream header magic 0x%x != 0x%x\n",
				       ctx->vf_id, le32_to_cpu(sh.magic),
				       VFMIG_WIRE_MAGIC);
			return -EPROTO;
		}
		if (le32_to_cpu(sh.version) != VFMIG_STREAM_VERSION) {
			mlx5_core_warn(ctx->vfmig->pf_mdev,
				       "vfmig: vf %u: stream version %u unsupported (this kernel: %u)\n",
				       ctx->vf_id, le32_to_cpu(sh.version),
				       VFMIG_STREAM_VERSION);
			return -EOPNOTSUPP;
		}

		ctx->hp_expected	= le64_to_cpu(sh.num_pages);
		ctx->hup_expected	= le32_to_cpu(sh.num_user_pages);
		ctx->manifest_crc_want	= le32_to_cpu(sh.manifest_crc32);
		ctx->manifest_crc_have	= 0;
		ctx->hp_seen		= 0;
		ctx->hup_seen		= 0;
		ctx->records_finalized	= false;
		ctx->stream_hdr_seen	= true;

		/*
		 * A source that recorded HOST_PAGE / HOST_USER_PAGE records
		 * needs a tracked destination to replay them into. Reject the
		 * mismatch here rather than at the first record.
		 */
		if ((ctx->hp_expected || ctx->hup_expected) && !ctx->iova_dom) {
			mlx5_core_warn(ctx->vfmig->pf_mdev,
				       "vfmig: vf %u: stream declares %llu HOST_PAGE + %llu HOST_USER_PAGE records but destination not SET_TRACKED'd\n",
				       ctx->vf_id,
				       (unsigned long long)ctx->hp_expected,
				       (unsigned long long)ctx->hup_expected);
			return -EINVAL;
		}

		/*
		 * Zero-record stream: no replays will arrive, so the manifest
		 * CRC (folded over zero bytes on the SAVE side) must be the
		 * crc32_le initial value of 0. Verify + arm now, since
		 * HP_REPLAY / HUP_REPLAY finalize will never be reached.
		 */
		if (ctx->hp_expected == 0 && ctx->hup_expected == 0) {
			if (ctx->manifest_crc_want != 0) {
				mlx5_core_warn(ctx->vfmig->pf_mdev,
					       "vfmig: vf %u: 0 records but non-zero manifest CRC 0x%08x\n",
					       ctx->vf_id,
					       ctx->manifest_crc_want);
				return -EPROTO;
			}
			if (ctx->iova_dom)
				vfmig_iova_arm_drift_detection(ctx->iova_dom);
			ctx->records_finalized = true;
		}

		ctx->state = VFMIG_LS_READ_HEADER;
		*progressed = true;
		return 0;
	}
	case VFMIG_LS_HP_READ_SUBHDR: {
		size_t need = sizeof(ctx->hp_subhdr_buf) -
			      ctx->hp_subhdr_filled;
		size_t take = min(need, *left);
		struct vfmig_host_page_record subhdr;
		u64 declared_payload;
		u32 hp_flags;
		u32 slot_id;

		if (take) {
			if (copy_from_user(ctx->hp_subhdr_buf +
						   ctx->hp_subhdr_filled,
					   *ubuf, take))
				return -EFAULT;
			ctx->hp_subhdr_filled += take;
			*ubuf += take;
			*left -= take;
			*progressed = true;
		}
		if (ctx->hp_subhdr_filled < sizeof(ctx->hp_subhdr_buf))
			return 0;

		memcpy(&subhdr, ctx->hp_subhdr_buf, sizeof(subhdr));
		slot_id			= le32_to_cpu(subhdr.slot_id);
		hp_flags		= le32_to_cpu(subhdr.flags);
		ctx->hp_instance_key	= le64_to_cpu(subhdr.instance_key);
		ctx->hp_iova		= le64_to_cpu(subhdr.iova);
		ctx->hp_len		= le64_to_cpu(subhdr.len);

		if (hp_flags) {
			mlx5_core_warn(ctx->vfmig->pf_mdev,
				       "vfmig: vf %u: HOST_PAGE flags=0x%x set (reserved, must be 0)\n",
				       ctx->vf_id, hp_flags);
			return -EOPNOTSUPP;
		}
		if (slot_id <= VFMIG_SLOT_INVALID || slot_id >= VFMIG_SLOT_NR) {
			mlx5_core_warn(ctx->vfmig->pf_mdev,
				       "vfmig: vf %u: HOST_PAGE slot_id %u out of range\n",
				       ctx->vf_id, slot_id);
			return -EPROTO;
		}
		ctx->hp_slot = (enum vfmig_iova_slot)slot_id;

		declared_payload = ctx->record_size -
				   sizeof(struct vfmig_host_page_record);
		if (ctx->hp_len != declared_payload ||
		    ctx->hp_len == 0 ||
		    ctx->hp_len > VFMIG_HOST_PAGE_MAX_LEN ||
		    !IS_ALIGNED(ctx->hp_len, VFMIG_IOVA_GRANULE) ||
		    !IS_ALIGNED(ctx->hp_iova, VFMIG_IOVA_GRANULE)) {
			mlx5_core_warn(ctx->vfmig->pf_mdev,
				       "vfmig: vf %u: malformed HOST_PAGE iova=0x%llx len=%llu (rec=%llu)\n",
				       ctx->vf_id,
				       (unsigned long long)ctx->hp_iova,
				       (unsigned long long)ctx->hp_len,
				       (unsigned long long)ctx->record_size);
			return -EINVAL;
		}

		ctx->hp_contents = kvmalloc(ctx->hp_len, GFP_KERNEL);
		if (!ctx->hp_contents)
			return -ENOMEM;
		ctx->hp_filled = 0;
		ctx->state = VFMIG_LS_HP_READ_DATA;
		*progressed = true;
		return 0;
	}
	case VFMIG_LS_HP_READ_DATA: {
		size_t need = ctx->hp_len - ctx->hp_filled;
		size_t take = min(need, *left);

		if (take) {
			if (copy_from_user((u8 *)ctx->hp_contents +
						   ctx->hp_filled,
					   *ubuf, take))
				return -EFAULT;
			ctx->hp_filled += take;
			*ubuf += take;
			*left -= take;
			*progressed = true;
		}
		if (ctx->hp_filled == ctx->hp_len) {
			ctx->state = VFMIG_LS_HP_REPLAY;
			*progressed = true;
		}
		return 0;
	}
	case VFMIG_LS_HP_REPLAY: {
		struct vfmig_host_page_record subhdr;

		err = vfmig_iova_replay_page(ctx->iova_dom, ctx->hp_slot,
					     ctx->hp_instance_key,
					     ctx->hp_iova, ctx->hp_contents,
					     ctx->hp_len);
		kvfree(ctx->hp_contents);
		ctx->hp_contents = NULL;
		if (err) {
			mlx5_core_warn(ctx->vfmig->pf_mdev,
				       "vfmig: vf %u: replay_page(slot=%u key=0x%llx iova=0x%llx len=%llu) failed: %d\n",
				       ctx->vf_id, ctx->hp_slot,
				       (unsigned long long)ctx->hp_instance_key,
				       (unsigned long long)ctx->hp_iova,
				       (unsigned long long)ctx->hp_len, err);
			return err;
		}

		/*
		 * Fold this record's identity tuple into the running manifest
		 * CRC, re-encoding from ctx->hp_* so the hashed bytes match
		 * the SAVE side exactly regardless of struct padding.
		 */
		subhdr.slot_id	    = cpu_to_le32(ctx->hp_slot);
		subhdr.flags	    = 0;
		subhdr.instance_key = cpu_to_le64(ctx->hp_instance_key);
		subhdr.iova	    = cpu_to_le64(ctx->hp_iova);
		subhdr.len	    = cpu_to_le64(ctx->hp_len);
		ctx->manifest_crc_have =
			crc32_le(ctx->manifest_crc_have,
				 (const u8 *)&subhdr.slot_id,
				 sizeof(subhdr.slot_id));
		ctx->manifest_crc_have =
			crc32_le(ctx->manifest_crc_have,
				 (const u8 *)&subhdr.flags,
				 sizeof(subhdr.flags));
		ctx->manifest_crc_have =
			crc32_le(ctx->manifest_crc_have,
				 (const u8 *)&subhdr.instance_key,
				 sizeof(subhdr.instance_key));
		ctx->manifest_crc_have =
			crc32_le(ctx->manifest_crc_have,
				 (const u8 *)&subhdr.iova,
				 sizeof(subhdr.iova));
		ctx->manifest_crc_have =
			crc32_le(ctx->manifest_crc_have,
				 (const u8 *)&subhdr.len,
				 sizeof(subhdr.len));

		ctx->hp_seen++;
		mlx5_core_dbg(ctx->vfmig->pf_mdev,
			      "vfmig: vf %u: replayed HOST_PAGE %llu/%llu slot=%u iova=0x%llx len=%llu\n",
			      ctx->vf_id,
			      (unsigned long long)ctx->hp_seen,
			      (unsigned long long)ctx->hp_expected,
			      ctx->hp_slot,
			      (unsigned long long)ctx->hp_iova,
			      (unsigned long long)ctx->hp_len);

		err = vfmig_load_maybe_finalize_records(ctx);
		if (err)
			return err;

		ctx->state = VFMIG_LS_READ_HEADER;
		*progressed = true;
		return 0;
	}
	case VFMIG_LS_HUP_READ_SUBHDR: {
		size_t need = sizeof(ctx->hup_subhdr_buf) -
			      ctx->hup_subhdr_filled;
		size_t take = min(need, *left);
		struct vfmig_host_user_page_record subhdr;
		u32 hup_flags;
		u32 hup_reserved;
		u8 kind;

		if (take) {
			if (copy_from_user(ctx->hup_subhdr_buf +
						   ctx->hup_subhdr_filled,
					   *ubuf, take))
				return -EFAULT;
			ctx->hup_subhdr_filled += take;
			*ubuf += take;
			*left -= take;
			*progressed = true;
		}
		if (ctx->hup_subhdr_filled < sizeof(ctx->hup_subhdr_buf))
			return 0;

		memcpy(&subhdr, ctx->hup_subhdr_buf, sizeof(subhdr));
		hup_flags		 = le32_to_cpu(subhdr.flags);
		hup_reserved		 = le32_to_cpu(subhdr.reserved);
		ctx->hup_instance_key	 = le64_to_cpu(subhdr.instance_key);
		ctx->hup_iova		 = le64_to_cpu(subhdr.iova);
		ctx->hup_len		 = le64_to_cpu(subhdr.len);

		if (hup_flags || hup_reserved) {
			mlx5_core_warn(ctx->vfmig->pf_mdev,
				       "vfmig: vf %u: HOST_USER_PAGE flags=0x%x reserved=0x%x set (must be 0)\n",
				       ctx->vf_id, hup_flags, hup_reserved);
			return -EOPNOTSUPP;
		}

		kind = VFMIG_HUOBJ_KIND(ctx->hup_instance_key);
		if (kind == VFMIG_HUOBJ_KIND_NONE ||
		    kind >= VFMIG_HUOBJ_KIND_NR) {
			mlx5_core_warn(ctx->vfmig->pf_mdev,
				       "vfmig: vf %u: HOST_USER_PAGE kind %u out of range\n",
				       ctx->vf_id, kind);
			return -EPROTO;
		}
		if (ctx->hup_len == 0 ||
		    !IS_ALIGNED(ctx->hup_len, VFMIG_IOVA_GRANULE) ||
		    !IS_ALIGNED(ctx->hup_iova, VFMIG_IOVA_GRANULE)) {
			mlx5_core_warn(ctx->vfmig->pf_mdev,
				       "vfmig: vf %u: malformed HOST_USER_PAGE iova=0x%llx len=%llu\n",
				       ctx->vf_id,
				       (unsigned long long)ctx->hup_iova,
				       (unsigned long long)ctx->hup_len);
			return -EINVAL;
		}

		ctx->state = VFMIG_LS_HUP_REPLAY;
		*progressed = true;
		return 0;
	}
	case VFMIG_LS_HUP_REPLAY: {
		struct vfmig_host_user_page_record subhdr;

		err = vfmig_iova_replay_external(ctx->iova_dom,
						 VFMIG_SLOT_USER_PAGE,
						 ctx->hup_instance_key,
						 ctx->hup_iova, ctx->hup_len);
		if (err) {
			mlx5_core_warn(ctx->vfmig->pf_mdev,
				       "vfmig: vf %u: replay_external(key=0x%llx iova=0x%llx len=%llu) failed: %d\n",
				       ctx->vf_id,
				       (unsigned long long)ctx->hup_instance_key,
				       (unsigned long long)ctx->hup_iova,
				       (unsigned long long)ctx->hup_len, err);
			return err;
		}

		/*
		 * Fold this record's identity tuple into the running manifest
		 * CRC, continuing from the HOST_PAGE pass and re-encoding from
		 * ctx->hup_* so the hashed bytes match the SAVE side exactly
		 * regardless of struct padding (flags/reserved are always 0).
		 */
		subhdr.flags	    = 0;
		subhdr.reserved	    = 0;
		subhdr.instance_key = cpu_to_le64(ctx->hup_instance_key);
		subhdr.iova	    = cpu_to_le64(ctx->hup_iova);
		subhdr.len	    = cpu_to_le64(ctx->hup_len);
		ctx->manifest_crc_have =
			crc32_le(ctx->manifest_crc_have,
				 (const u8 *)&subhdr.flags,
				 sizeof(subhdr.flags));
		ctx->manifest_crc_have =
			crc32_le(ctx->manifest_crc_have,
				 (const u8 *)&subhdr.reserved,
				 sizeof(subhdr.reserved));
		ctx->manifest_crc_have =
			crc32_le(ctx->manifest_crc_have,
				 (const u8 *)&subhdr.instance_key,
				 sizeof(subhdr.instance_key));
		ctx->manifest_crc_have =
			crc32_le(ctx->manifest_crc_have,
				 (const u8 *)&subhdr.iova,
				 sizeof(subhdr.iova));
		ctx->manifest_crc_have =
			crc32_le(ctx->manifest_crc_have,
				 (const u8 *)&subhdr.len,
				 sizeof(subhdr.len));

		ctx->hup_seen++;
		mlx5_core_dbg(ctx->vfmig->pf_mdev,
			      "vfmig: vf %u: replayed HOST_USER_PAGE %llu/%llu key=0x%llx iova=0x%llx len=%llu\n",
			      ctx->vf_id,
			      (unsigned long long)ctx->hup_seen,
			      (unsigned long long)ctx->hup_expected,
			      (unsigned long long)ctx->hup_instance_key,
			      (unsigned long long)ctx->hup_iova,
			      (unsigned long long)ctx->hup_len);

		err = vfmig_load_maybe_finalize_records(ctx);
		if (err)
			return err;

		ctx->state = VFMIG_LS_READ_HEADER;
		*progressed = true;
		return 0;
	}
	case VFMIG_LS_KOBJ_READ: {
		size_t take = min(sizeof(ctx->kobj_buf) - ctx->kobj_filled,
				  *left);
		struct vfmig_host_kobj_record rec;
		u32 kind, key, id;

		if (take) {
			if (copy_from_user(ctx->kobj_buf + ctx->kobj_filled,
					   *ubuf, take))
				return -EFAULT;
			ctx->kobj_filled += take;
			*ubuf += take;
			*left -= take;
			*progressed = true;
		}
		if (ctx->kobj_filled < sizeof(ctx->kobj_buf))
			return 0;

		memcpy(&rec, ctx->kobj_buf, sizeof(rec));
		kind = le32_to_cpu(rec.kind);
		key  = le32_to_cpu(rec.key);
		id   = le32_to_cpu(rec.id);
		if (rec.flags || !kind || kind >= MLX5_VFMIG_KOBJ_NR || !id) {
			mlx5_core_warn(ctx->vfmig->pf_mdev,
				       "vfmig: vf %u: malformed HOST_KOBJ kind %u key %u id 0x%x flags 0x%x\n",
				       ctx->vf_id, kind, key, id,
				       le32_to_cpu(rec.flags));
			return -EPROTO;
		}
		err = vfmig_iova_kobj_replay(ctx->iova_dom, kind, key, id);
		if (err) {
			mlx5_core_warn(ctx->vfmig->pf_mdev,
				       "vfmig: vf %u: replaying HOST_KOBJ kind %u key %u id 0x%x failed: %d\n",
				       ctx->vf_id, kind, key, id, err);
			return err;
		}
		mlx5_core_dbg(ctx->vfmig->pf_mdev,
			      "vfmig: vf %u: replayed HOST_KOBJ kind %u key %u id 0x%x\n",
			      ctx->vf_id, kind, key, id);

		ctx->state = VFMIG_LS_READ_HEADER;
		*progressed = true;
		return 0;
	}
	case VFMIG_LS_PREP_IMAGE:
		want_npages = max_t(u32, 1,
				    DIV_ROUND_UP(ctx->record_size, PAGE_SIZE));
		err = vfmig_load_prepare_image(ctx, want_npages);
		if (err)
			return err;
		ctx->state = VFMIG_LS_READ_IMAGE;
		*progressed = true;
		return 0;
	case VFMIG_LS_READ_IMAGE: {
		size_t want = min_t(size_t, *left,
				    ctx->record_size - ctx->image_filled);

		if (want) {
			n = vfmig_load_consume_image(ctx, *ubuf, want);
			if (n < 0)
				return n;
			*ubuf += n;
			*left -= n;
			*progressed = n > 0;
		}
		if (ctx->image_filled == ctx->record_size) {
			ctx->state = VFMIG_LS_LOAD_IMAGE;
			*progressed = true;
		}
		return 0;
	}
	case VFMIG_LS_LOAD_IMAGE:
		err = vfmig_load_run_load(ctx);
		if (err)
			return err;
		*progressed = true;
		return 0;
	case VFMIG_LS_DONE:
	default:
		/* A complete blob was already loaded; trailing bytes are junk. */
		if (*left)
			return -EINVAL;
		return 0;
	}
}

static ssize_t vfmig_load_write(struct file *filp, const char __user *ubuf,
				size_t count, loff_t *ppos)
{
	struct mlx5_vfmig_load_ctx *ctx = filp->private_data;
	struct mlx5_vfmig_pf *vfmig = ctx->vfmig;
	const char __user *cursor = ubuf;
	size_t left = count;
	ssize_t produced;
	bool progressed;
	int err = 0;

	if (!count)
		return 0;

	mutex_lock(&ctx->io_lock);
	down_read(&vfmig->lock);
	if (vfmig->dead || ctx->resources_freed) {
		err = -ENODEV;
		goto out;
	}

	/* Drive the FSM until it stops making progress (not until left==0). */
	for (;;) {
		progressed = false;
		err = vfmig_load_step(ctx, &cursor, &left, &progressed);
		if (err || !progressed)
			break;
	}
out:
	up_read(&vfmig->lock);
	mutex_unlock(&ctx->io_lock);

	produced = (ssize_t)(count - left);
	if (!produced && err)
		return err;
	return produced;	/* stream_open() => ppos is NULL, leave it */
}

/* Free @ctx's firmware-tied resources in place (no hand-off). */
static void vfmig_load_drop_resources(struct mlx5_vfmig_load_ctx *ctx,
				      struct mlx5_core_dev *pf_mdev)
{
	if (ctx->image_mkey_created) {
		mlx5_core_destroy_mkey(pf_mdev, ctx->image_mkey);
		ctx->image_mkey_created = false;
	}
	if (ctx->image_dma_mapped) {
		vfmig_unregister_dma_pages(pf_mdev, ctx->image_npages,
					   ctx->image_mkey_in,
					   &ctx->image_dma_state,
					   DMA_TO_DEVICE);
		ctx->image_dma_mapped = false;
	}
	kvfree(ctx->image_mkey_in);
	ctx->image_mkey_in = NULL;

	if (ctx->pd_allocated) {
		mlx5_core_dealloc_pd(pf_mdev, ctx->pdn);
		ctx->pd_allocated = false;
	}
}

/*
 * Release the firmware-tied resources held by @ctx. Idempotent via
 * @resources_freed. Called from release() (pf_mdev alive) or pf_cleanup()
 * (before pf_mdev is NULLed). Caller holds vfmig->lock.
 *
 * On the happy path -- a complete blob was staged and the PF is still
 * live -- the resources are transferred into the PF's per-VF
 * pending_load slot rather than freed, so the next probe can apply the
 * LOAD. @image_transferred then suppresses the page free in release().
 * Otherwise (partial/empty write, or PF going away) everything is freed.
 */
static void vfmig_load_release_resources(struct mlx5_vfmig_load_ctx *ctx)
{
	struct mlx5_vfmig_pf *vfmig = ctx->vfmig;
	struct mlx5_core_dev *pf_mdev = vfmig->pf_mdev;
	struct mlx5_vfmig_vf_load *load;
	int err;

	if (ctx->resources_freed)
		return;
	ctx->resources_freed = true;

	if (!pf_mdev)
		return;

	/* Nothing staged, or PF tearing down: just free in place. */
	if (!ctx->image_staged || vfmig->dead) {
		vfmig_load_drop_resources(ctx, pf_mdev);
		return;
	}

	load = kzalloc(sizeof(*load), GFP_KERNEL);
	if (!load) {
		/* Can't stage without a slot; drop the blob (no lasting effect). */
		vfmig_load_drop_resources(ctx, pf_mdev);
		return;
	}

	load->vf_id = ctx->vf_id;
	load->vhca_id = ctx->vhca_id;
	load->pdn = ctx->pdn;
	load->pd_allocated = ctx->pd_allocated;
	load->mkey_in = ctx->image_mkey_in;
	load->mkey = ctx->image_mkey;
	load->mkey_created = ctx->image_mkey_created;
	load->dma_mapped = ctx->image_dma_mapped;
	load->dma_state = ctx->image_dma_state;
	load->pages = ctx->image_pages;
	load->npages = ctx->image_npages;
	load->record_size = ctx->record_size;

	mutex_lock(&vfmig->ctxs_lock);
	err = vfmig_install_pending_load_locked(vfmig, load);
	mutex_unlock(&vfmig->ctxs_lock);

	/*
	 * Either way the resources now belong to @load: on success the
	 * slot owns them until the next probe; on failure we free @load
	 * (which frees them). Detach from @ctx so release() won't double
	 * free the pages.
	 */
	ctx->image_transferred = true;
	ctx->pd_allocated = false;
	ctx->image_mkey_in = NULL;
	ctx->image_mkey_created = false;
	ctx->image_dma_mapped = false;
	ctx->image_pages = NULL;
	ctx->image_npages = 0;

	if (err) {
		mlx5_core_warn(pf_mdev,
			       "vfmig: vf %u (vhca_id 0x%04x): install pending_load failed: %d\n",
			       ctx->vf_id, ctx->vhca_id, err);
		vfmig_vf_load_destroy(pf_mdev, load);
		return;
	}

	mlx5_core_info(pf_mdev,
		       "vfmig: staged %llu bytes of LOAD state for vf %u (vhca_id 0x%04x); next probe will apply\n",
		       ctx->record_size, ctx->vf_id, ctx->vhca_id);
}

static int vfmig_load_release(struct inode *inode, struct file *filp)
{
	struct mlx5_vfmig_load_ctx *ctx = filp->private_data;
	struct mlx5_vfmig_pf *vfmig = ctx->vfmig;

	down_read(&vfmig->lock);
	if (!vfmig->dead) {
		vfmig_load_release_resources(ctx);
		/*
		 * With every promised HOST_PAGE replayed and the FW_DATA blob
		 * staged, rewind the domain's per-slot bump cursors so the
		 * destination VF's next probe re-claims the replayed pages
		 * (carrying the source's contents) from each slot base in the
		 * same order the source allocated them. Once per fd; only on
		 * the staged-blob path (a partial/aborted LOAD leaves the
		 * cursors alone).
		 */
		if (ctx->iova_dom && ctx->image_staged &&
		    !ctx->cursor_reset_done) {
			vfmig_iova_reset_cursor(ctx->iova_dom);
			ctx->cursor_reset_done = true;
		}
	}
	up_read(&vfmig->lock);

	mutex_lock(&vfmig->ctxs_lock);
	list_del(&ctx->node);
	mutex_unlock(&vfmig->ctxs_lock);

	/* Pages were handed to the pending_load slot iff transferred. */
	if (!ctx->image_transferred)
		vfmig_free_pages(ctx->image_pages, ctx->image_npages);
	/* Free a HOST_PAGE payload left over from a partial mid-record close. */
	kvfree(ctx->hp_contents);
	mutex_destroy(&ctx->io_lock);
	vfmig_pf_put(vfmig);
	kfree(ctx);
	return 0;
}

static const struct file_operations mlx5_vfmig_load_fops = {
	.owner		= THIS_MODULE,
	.write		= vfmig_load_write,
	.release	= vfmig_load_release,
};

/*
 * Set up a LOAD session for @vf_id: resolve vhca_id, allocate a PD, and
 * hand back a write-only anon-inode fd. The staging buffer + MKEY are
 * allocated lazily once write() sees the record size. Closing the fd
 * after a complete blob stages it into the VF's pending_load slot; the
 * VF's next mlx5_core probe suspends the freshly-enabled VHCA, issues
 * LOAD_VHCA_STATE and resumes it. No VHCA suspend is required (or
 * performed) at ioctl time. Caller holds vfmig->lock for read.
 */
static long vfmig_ioc_load_vhca_state(struct mlx5_vfmig_pf *vfmig,
				      void __user *uarg)
{
	struct mlx5_core_dev *pf_mdev = vfmig->pf_mdev;
	struct mlx5_vfmig_load_state arg;
	struct mlx5_vfmig_load_ctx *ctx;
	struct mlx5_core_sriov *sriov;
	bool migratable = false;
	struct file *file;
	u16 vhca_id;
	int fd, err;

	if (copy_from_user(&arg, uarg, sizeof(arg)))
		return -EFAULT;
	if (arg.flags || arg.reserved)
		return -EINVAL;

	sriov = &pf_mdev->priv.sriov;
	if (arg.vf_id >= sriov->num_vfs)
		return -EINVAL;

	err = vfmig_check_pf_migration_caps(pf_mdev);
	if (err)
		return err;

	err = vfmig_query_vf_migratable(pf_mdev, arg.vf_id, &migratable);
	if (err)
		return err;
	if (!migratable) {
		mlx5_core_warn(pf_mdev,
			       "vfmig: vf %u is not migration-enabled\n",
			       arg.vf_id);
		return -EOPNOTSUPP;
	}

	err = vfmig_query_vhca_id(pf_mdev, arg.vf_id + 1, &vhca_id);
	if (err)
		return err;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	INIT_LIST_HEAD(&ctx->node);
	mutex_init(&ctx->io_lock);
	ctx->vf_id = arg.vf_id;
	ctx->vhca_id = vhca_id;
	ctx->state = VFMIG_LS_READ_HEADER;

	/* Claim vf_id atomically vs other SAVE/LOAD sessions. */
	mutex_lock(&vfmig->ctxs_lock);
	if (vfmig_vf_id_busy_locked(vfmig, ctx->vf_id)) {
		mutex_unlock(&vfmig->ctxs_lock);
		err = -EBUSY;
		goto err_claim;
	}
	vfmig_pf_get(vfmig);
	ctx->vfmig = vfmig;
	/*
	 * Capture the destination's IOVA domain (if SET_TRACKED'd) for
	 * HOST_PAGE replay. NULL for an untracked destination; the parser
	 * then rejects any HOST_PAGE-bearing blob. Guarded by ctxs_lock,
	 * the same lock that publishes/takes iova_dom slots.
	 */
	ctx->iova_dom = vfmig->iova_dom[ctx->vf_id];
	list_add(&ctx->node, &vfmig->load_ctxs);
	mutex_unlock(&vfmig->ctxs_lock);

	err = mlx5_core_alloc_pd(pf_mdev, &ctx->pdn);
	if (err)
		goto err_res;
	ctx->pd_allocated = true;

	fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd < 0) {
		err = fd;
		goto err_res;
	}

	file = anon_inode_getfile("mlx5_vfmig_load", &mlx5_vfmig_load_fops,
				  ctx, O_WRONLY | O_CLOEXEC);
	if (IS_ERR(file)) {
		err = PTR_ERR(file);
		goto err_fd;
	}
	stream_open(file_inode(file), file);

	arg.load_fd = fd;
	if (copy_to_user(uarg, &arg, sizeof(arg))) {
		err = -EFAULT;
		goto err_file;
	}

	fd_install(fd, file);
	mlx5_core_info(pf_mdev,
		       "vfmig: LOAD session opened for vf %u (vhca_id 0x%04x)\n",
		       arg.vf_id, vhca_id);
	return 0;

err_file:
	/* fput() runs vfmig_load_release, which frees resources + ctx. */
	fput(file);
	put_unused_fd(fd);
	return err;
err_fd:
	put_unused_fd(fd);
err_res:
	vfmig_load_release_resources(ctx);
	vfmig_free_pages(ctx->image_pages, ctx->image_npages);
	mutex_lock(&vfmig->ctxs_lock);
	list_del(&ctx->node);
	mutex_unlock(&vfmig->ctxs_lock);
	vfmig_pf_put(vfmig);
	mutex_destroy(&ctx->io_lock);
	kfree(ctx);
	return err;
err_claim:
	mutex_destroy(&ctx->io_lock);
	kfree(ctx);
	return err;
}

/*
 * Return an unbound VF to its post-SR-IOV-enable state: FLR it, drop the
 * restored latch, any staged LOAD and the datapath/defer-resume state,
 * and destroy its IOVA arena, leaving it untracked. The VF device_lock is
 * held throughout, so nothing can bind it while its state is
 * inconsistent.
 */
static long vfmig_ioc_recycle_vf(struct mlx5_vfmig_pf *vfmig,
				 void __user *uarg)
{
	struct mlx5_core_dev *pf_mdev = vfmig->pf_mdev;
	struct mlx5_vfmig_vf_load *load = NULL;
	struct vfmig_iova_domain *old_dom;
	struct mlx5_vfmig_recycle_vf arg;
	struct mlx5_core_sriov *sriov;
	struct pci_dev *vf_pdev;
	unsigned int left = 0;
	bool was_restored;
	int err = 0;

	if (copy_from_user(&arg, uarg, sizeof(arg)))
		return -EFAULT;
	if (arg.flags)
		return -EINVAL;

	sriov = &pf_mdev->priv.sriov;
	if (arg.vf_id >= sriov->num_vfs || arg.vf_id >= vfmig->max_vfs)
		return -EINVAL;

	vf_pdev = vfmig_get_vf_pdev(pf_mdev->pdev, arg.vf_id);
	if (!vf_pdev) {
		mlx5_core_warn(pf_mdev,
			       "vfmig: RECYCLE_VF vf %u: VF pci_dev lookup failed\n",
			       arg.vf_id);
		return -ENODEV;
	}

	device_lock(&vf_pdev->dev);
	if (vf_pdev->dev.driver) {
		mlx5_core_warn(pf_mdev,
			       "vfmig: RECYCLE_VF vf %u rejected: VF is bound to %s (must be unbound first)\n",
			       arg.vf_id, vf_pdev->dev.driver->name);
		err = -EBUSY;
		goto out_unlock;
	}

	mutex_lock(&vfmig->ctxs_lock);
	if (!uuid_is_null(&vfmig->vf_uuid[arg.vf_id])) {
		mlx5_core_warn(pf_mdev,
			       "vfmig: RECYCLE_VF vf %u rejected: UUID %pUb still stamped (clear it first)\n",
			       arg.vf_id, &vfmig->vf_uuid[arg.vf_id]);
		err = -EEXIST;
	} else if (vfmig_vf_id_busy_locked(vfmig, arg.vf_id)) {
		mlx5_core_warn(pf_mdev,
			       "vfmig: RECYCLE_VF vf %u rejected: SAVE/LOAD session open\n",
			       arg.vf_id);
		err = -EBUSY;
	}
	mutex_unlock(&vfmig->ctxs_lock);
	if (err)
		goto out_unlock;

	err = pci_reset_function_locked(vf_pdev);
	if (err) {
		mlx5_core_warn(pf_mdev,
			       "vfmig: RECYCLE_VF vf %u: FLR failed: %d, state unchanged\n",
			       arg.vf_id, err);
		goto out_unlock;
	}

	mutex_lock(&vfmig->ctxs_lock);
	load = vfmig->pending_load[arg.vf_id];
	vfmig->pending_load[arg.vf_id] = NULL;
	was_restored = test_and_clear_bit(arg.vf_id, vfmig->restored);
	sriov->vfs_ctx[arg.vf_id].vfmig_dp_state = MLX5_VFMIG_DP_RUNNING;
	sriov->vfs_ctx[arg.vf_id].vfmig_defer_resume = 0;
	old_dom = vfmig->iova_dom[arg.vf_id];
	vfmig->iova_dom[arg.vf_id] = NULL;
	mutex_unlock(&vfmig->ctxs_lock);

	if (old_dom) {
		left = vfmig_iova_nr_pages(old_dom);
		vfmig_iova_domain_destroy(old_dom);
	}

	mlx5_core_info(pf_mdev,
		       "vfmig: vf %u recycled (restored=%d staged_load=%d was_tracked=%d, %u arena pages dropped)\n",
		       arg.vf_id, was_restored, !!load, !!old_dom, left);

out_unlock:
	device_unlock(&vf_pdev->dev);
	pci_dev_put(vf_pdev);

	if (load)
		vfmig_vf_load_destroy(pf_mdev, load);
	return err;
}

static long vfmig_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct mlx5_vfmig_pf *vfmig = filp->private_data;
	void __user *uarg = (void __user *)arg;
	long ret;

	if (cmd == MLX5_VFMIG_IOC_RX_FENCE)
		return vfmig_ioc_rx_fence(vfmig, uarg);

	down_read(&vfmig->lock);
	if (vfmig->dead) {
		ret = -ENODEV;
		goto out;
	}

	switch (cmd) {
	case MLX5_VFMIG_IOC_MARK_RESTORED:
		ret = vfmig_ioc_mark_restored(vfmig, uarg);
		break;
	case MLX5_VFMIG_IOC_GET_VHCA_ID:
		ret = vfmig_ioc_get_vhca_id(vfmig, uarg);
		break;
	case MLX5_VFMIG_IOC_QUERY_VF:
		ret = vfmig_ioc_query_vf(vfmig, uarg);
		break;
	case MLX5_VFMIG_IOC_SET_VF_UUID:
		ret = vfmig_ioc_set_vf_uuid(vfmig, uarg);
		break;
	case MLX5_VFMIG_IOC_RECYCLE_VF:
		ret = vfmig_ioc_recycle_vf(vfmig, uarg);
		break;
	case MLX5_VFMIG_IOC_SET_TRACKED:
		ret = vfmig_ioc_set_tracked(vfmig, uarg);
		break;
	case MLX5_VFMIG_IOC_ENABLE_MIGRATABLE:
		ret = vfmig_ioc_enable_migratable(vfmig, uarg);
		break;
	case MLX5_VFMIG_IOC_SUSPEND_VHCA:
		ret = vfmig_ioc_suspend_vhca(vfmig, uarg);
		break;
	case MLX5_VFMIG_IOC_RESUME_VHCA:
		ret = vfmig_ioc_resume_vhca(vfmig, uarg);
		break;
	case MLX5_VFMIG_IOC_SAVE_VHCA_STATE:
		ret = vfmig_ioc_save_vhca_state(vfmig, uarg);
		break;
	case MLX5_VFMIG_IOC_LOAD_VHCA_STATE:
		ret = vfmig_ioc_load_vhca_state(vfmig, uarg);
		break;
	default:
		ret = -ENOTTY;
		break;
	}
out:
	up_read(&vfmig->lock);

	return ret;
}

static const struct file_operations mlx5_vfmig_fops = {
	.owner		= THIS_MODULE,
	.open		= vfmig_open,
	.release	= vfmig_release,
	.unlocked_ioctl	= vfmig_ioctl,
	.compat_ioctl	= compat_ptr_ioctl,
};

/* -------- probe-time restore hooks (called from mlx5_core main.c) ------- */

/*
 * Test-and-clear the restored latch for the VF backed by @vf_dev, and
 * report the vhca_id of any staged LOAD. Called once from the VF's
 * mlx5_function_enable(); a true return tells the probe to skip INIT_HCA
 * (and, if a slot is staged, to call mlx5_vfmig_vf_apply_pending_load()).
 */
bool mlx5_vfmig_vf_consume_restored(struct mlx5_core_dev *vf_dev,
				    u16 *vhca_id_out)
{
	struct pci_dev *vf_pdev = vf_dev->pdev;
	struct mlx5_core_dev *pf_mdev;
	struct mlx5_vfmig_pf *vfmig;
	bool restored = false;
	int vf_id;

	if (!vf_pdev || !vf_pdev->is_virtfn)
		return false;
	vf_id = pci_iov_vf_id(vf_pdev);
	if (vf_id < 0)
		return false;

	pf_mdev = mlx5_vf_get_core_dev(vf_pdev);
	if (!pf_mdev)
		return false;

	vfmig = pf_mdev->priv.vfmig;
	if (vfmig && (u32)vf_id < vfmig->max_vfs &&
	    test_and_clear_bit(vf_id, vfmig->restored)) {
		struct mlx5_vfmig_vf_load *load;

		mutex_lock(&vfmig->ctxs_lock);
		load = vfmig->pending_load[vf_id];
		if (vhca_id_out)
			*vhca_id_out = load ? load->vhca_id : 0;
		mutex_unlock(&vfmig->ctxs_lock);
		restored = true;
	}

	mlx5_vf_put_core_dev(pf_mdev);
	return restored;
}

/* Detach @vf_id's staged LOAD slot. Caller holds vfmig->ctxs_lock. */
static struct mlx5_vfmig_vf_load *
vfmig_take_pending_load_locked(struct mlx5_vfmig_pf *vfmig, u32 vf_id)
{
	struct mlx5_vfmig_vf_load *load;

	if (vf_id >= vfmig->max_vfs)
		return NULL;

	load = vfmig->pending_load[vf_id];
	vfmig->pending_load[vf_id] = NULL;
	return load;
}

/*
 * Apply the LOAD blob staged for the VF backed by @vf_dev, if any.
 * Called from the VF's mlx5_function_enable() right after the VHCA has
 * been (re-)enabled by the PF -- i.e. while the FW considers it RUNNING.
 * LOAD_VHCA_STATE is only valid on a fully-suspended VHCA, so walk
 * RUNNING -> STOP first, run LOAD, then walk STOP -> RUNNING so the
 * QUERY_ADAPTER the probe issues next has a live VHCA. A missing slot is
 * not an error (returns 0): a bare MARK_RESTORED sets the latch without
 * staging a blob.
 */
int mlx5_vfmig_vf_apply_pending_load(struct mlx5_core_dev *vf_dev)
{
	struct pci_dev *vf_pdev = vf_dev->pdev;
	struct mlx5_core_dev *pf_mdev;
	struct mlx5_vfmig_vf_load *load;
	struct mlx5_vfmig_pf *vfmig;
	u8 reached;
	int vf_id;
	int err = 0;

	if (!vf_pdev || !vf_pdev->is_virtfn)
		return 0;
	vf_id = pci_iov_vf_id(vf_pdev);
	if (vf_id < 0)
		return 0;

	pf_mdev = mlx5_vf_get_core_dev(vf_pdev);
	if (!pf_mdev)
		return 0;

	vfmig = pf_mdev->priv.vfmig;
	if (!vfmig) {
		mlx5_vf_put_core_dev(pf_mdev);
		return 0;
	}

	/*
	 * Pin the vfmig context so its locks survive a racing pf_cleanup;
	 * the PF mdev itself is pinned by mlx5_vf_get_core_dev().
	 */
	vfmig_pf_get(vfmig);
	down_read(&vfmig->lock);
	if (vfmig->dead)
		goto out_unlock;

	mutex_lock(&vfmig->ctxs_lock);
	load = vfmig_take_pending_load_locked(vfmig, vf_id);
	mutex_unlock(&vfmig->ctxs_lock);
	if (!load)
		goto out_unlock;

	mlx5_core_dbg(pf_mdev,
		      "vfmig: apply pending LOAD: vf %u vhca_id 0x%04x mkey 0x%08x size %llu\n",
		      load->vf_id, load->vhca_id, load->mkey, load->record_size);

	err = vfmig_dp_transition(pf_mdev, load->vhca_id, MLX5_VFMIG_DP_RUNNING,
				  MLX5_VFMIG_DP_STOP, &reached);
	if (err)
		goto out_destroy;

	err = vfmig_cmd_load_vhca_state(pf_mdev, load->vhca_id, load->mkey,
					load->record_size);
	if (err) {
		mlx5_core_warn(pf_mdev,
			       "vfmig: LOAD_VHCA_STATE vf %u (vhca_id 0x%04x) size %llu failed: %d\n",
			       load->vf_id, load->vhca_id, load->record_size,
			       err);
		goto out_destroy;
	}

	/*
	 * Snapshot-ordering restore mirror: if MARK_RESTORED { DEFER_RESUME }
	 * stamped this VF, leave the freshly-loaded VHCA parked at STOP and
	 * latch vfmig_dp_state = STOP. CRIU brings the datapath live with an
	 * explicit RESUME_VHCA at RESUME_DEVICES_LATE, once every MR/ring VMA
	 * has been restored. The one-shot hint is consumed here.
	 */
	if (pf_mdev->priv.sriov.vfs_ctx[vf_id].vfmig_defer_resume) {
		pf_mdev->priv.sriov.vfs_ctx[vf_id].vfmig_dp_state =
			MLX5_VFMIG_DP_STOP;
		pf_mdev->priv.sriov.vfs_ctx[vf_id].vfmig_defer_resume = 0;
		mlx5_core_info(pf_mdev,
			       "vfmig: applied %llu bytes of LOAD state to vf %u (vhca_id 0x%04x); resume deferred (parked for RESUME_DEVICES_LATE)\n",
			       load->record_size, load->vf_id, load->vhca_id);
		goto out_destroy;
	}

	err = vfmig_dp_transition(pf_mdev, load->vhca_id, MLX5_VFMIG_DP_STOP,
				  MLX5_VFMIG_DP_RUNNING, &reached);
	if (!err)
		mlx5_core_info(pf_mdev,
			       "vfmig: applied %llu bytes of LOAD state to vf %u (vhca_id 0x%04x); resumed\n",
			       load->record_size, load->vf_id, load->vhca_id);

out_destroy:
	vfmig_vf_load_destroy(pf_mdev, load);
out_unlock:
	up_read(&vfmig->lock);
	vfmig_pf_put(vfmig);
	mlx5_vf_put_core_dev(pf_mdev);
	return err;
}

struct vfmig_import_fwp_ctx {
	struct mlx5_core_dev *vf_dev;
	u32 imported;
	int err;
};

static int vfmig_import_fwp_cb(enum vfmig_iova_slot slot, u64 instance_key,
			       dma_addr_t iova, const void *vaddr, size_t len,
			       void *ctx)
{
	struct vfmig_import_fwp_ctx *ic = ctx;
	int err;

	/*
	 * Only FW_PAGE entries went through alloc_system_page() ->
	 * insert_page() on the source. The other slots (CMD_RING,
	 * EQ_BUF, FRAG_BUF, DB_PAGE, DMA_COHERENT) live in their own
	 * lifetime trackers (cmd ring buffer, struct mlx5_frag_buf,
	 * mlx5_db_pgdir, etc.) and never appear in priv->page_root_xa.
	 * Skip them here -- their reconstruction is the matching
	 * consumer's job.
	 */
	if (slot != VFMIG_SLOT_FW_PAGE)
		return 0;

	/*
	 * alloc_system_page() always allocates exactly PAGE_SIZE per
	 * call; the wire mirrors that 1:1. Defensive check rather than
	 * silently importing a malformed-len entry.
	 */
	if (WARN_ON_ONCE(len != PAGE_SIZE))
		return 0;

	/*
	 * function=0 is the VF reclaiming-its-own-pages encoding
	 * (func_id=0, ec_function=0). Matches what give_pages() passes
	 * on the source for VF-self give-pages events, which is the
	 * only flavour alloc_system_page() ever drives on a VF mdev.
	 */
	err = mlx5_pages_import_replayed_fw_page(ic->vf_dev, /*function=*/0,
						 (u64)iova);
	if (err) {
		ic->err = err;
		return err;
	}
	ic->imported++;
	return 0;
}

/*
 * Reconstitute mlx5_core's per-VF page rb-tree (priv->page_root_xa)
 * for a restored VF, mirroring the source's give_pages() output.
 *
 * On the source, every FW_PAGE the IOVA allocator handed out was
 * also recorded in priv->page_root_xa[function] via insert_page() in
 * alloc_system_page(); priv->fw_pages and priv->page_counters[VF]
 * tracked the running total. Both data structures together back
 * mlx5_reclaim_root_pages() at VF teardown: it walks page_root, calls
 * free_fwp() on each entry, and free_fwp()'s vfmig branch routes the
 * page back through vfmig_iova_free_slot().
 *
 * On the destination, vfmig_iova_replay_page() during LOAD installed
 * the IOVA mapping and the page contents, but it did NOT touch
 * page_root_xa -- the VF mdev didn't even exist yet (the LOAD ioctl
 * runs on the PF cdev pre-bind). Without this reconstruction step
 * the restored VF probes with an empty page_root for its own
 * function and:
 *
 *   - mlx5_reclaim_root_pages() at teardown finds nothing, returns 0
 *     pages reclaimed; FW thinks it still owns the pages and the
 *     IOVA allocator never frees them -> per-VF leak that grows
 *     unbounded with bind/unbind cycles.
 *   - any FW-initiated MANAGE_PAGES { take_pages } walks the (empty)
 *     rb-tree, returns -EEXIST/0-pages, and FW state diverges from
 *     mlx5_core's view.
 *   - priv->fw_pages and the per-type page_counters[] under-report
 *     by exactly the number of pages LOAD restored, tripping
 *     debug-kernel sanity checks in mlx5_destroy_mkey() and the
 *     pages_debugfs reader.
 *
 * Walks the per-VF deterministic IOVA domain in IOVA-ascending order
 * (matching the source's give-pages order, which is what
 * vfmig_iova_for_each guarantees) and calls
 * mlx5_pages_import_replayed_fw_page() for each FW_PAGE entry. Other
 * slots are skipped -- they live in their own consumer-side
 * lifetime trackers (cmd ring buffer, mlx5_frag_buf, mlx5_db_pgdir)
 * which the corresponding consumer reconstructs on its own probe.
 *
 * MUST run between the destination VF's mlx5_cmd_enable() (which
 * initialises priv->page_root_xa) and any FW give-pages event on the
 * restored VHCA. The current caller is the restored-VF branch of
 * mlx5_function_enable() in main.c, right after
 * mlx5_vfmig_vf_apply_pending_load() returns success and before
 * mlx5_start_health_poll().
 *
 * Returns 0 on success (including the no-domain / no-FW_PAGE-entries
 * case) or a negative errno from the first failed
 * mlx5_pages_import_replayed_fw_page(). On error, partial inserts
 * are NOT rolled back: the pages live in priv->page_root_xa and will
 * be reclaimed by mlx5_reclaim_root_pages() at VF teardown via the
 * same vfmig branch as a successful import. The probe should still
 * fail loudly via the err return so the operator sees the divergence.
 */
int mlx5_vfmig_vf_import_replayed_fw_pages(struct mlx5_core_dev *vf_dev)
{
	struct vfmig_iova_domain *dom;
	struct vfmig_import_fwp_ctx ic = { .vf_dev = vf_dev };
	struct pci_dev *vf_pdev;
	int err;

	if (!vf_dev)
		return 0;

	vf_pdev = vf_dev->pdev;
	if (!vf_pdev || !vf_pdev->is_virtfn)
		return 0;

	/*
	 * Read the IOVA domain off vf_dev->cmd, NOT via
	 * mlx5_vf_get_vfmig_iova_domain(): the latter takes the
	 * PF reference and goes through the cdev lookup path, which
	 * is heavier than what we need here and (more importantly)
	 * acquires intf_state_mutex on the PF -- a lock our caller
	 * (mlx5_function_enable) doesn't hold but would inherit a
	 * deadlock risk against if the lookup ever started running on
	 * a path that does. The cmd-side pointer was set by
	 * mlx5_cmd_enable() upstream of us and is guaranteed live for
	 * the duration of this VF probe (see vfmig.h docstring on
	 * mlx5_vf_get_vfmig_iova_domain for the lifetime contract).
	 */
	dom = vf_dev->cmd.vfmig_iova_dom;
	if (!dom)
		return 0;

	err = vfmig_iova_for_each(dom, vfmig_import_fwp_cb, &ic);
	if (err) {
		mlx5_core_warn(vf_dev,
			       "vfmig: import_replayed_fw_pages: failed after %u entries: %d\n",
			       ic.imported, err);
		return err;
	}

	mlx5_core_info(vf_dev,
		       "vfmig: imported %u replayed FW_PAGE entries into priv->page_root\n",
		       ic.imported);
	return 0;
}

/*
 * Destroy every staged-but-unconsumed pending_load slot and clear the
 * restored latch it set. pf_mdev must be alive (FW resource teardown).
 * Caller holds vfmig->lock; ctxs_lock is taken here and dropped around
 * the sleepable vfmig_vf_load_destroy() (which issues FW commands).
 */
static void vfmig_drop_pending_loads_locked(struct mlx5_vfmig_pf *vfmig)
{
	struct mlx5_core_dev *pf_mdev = vfmig->pf_mdev;
	u32 i;

	if (!pf_mdev)
		return;

	mutex_lock(&vfmig->ctxs_lock);
	for (i = 0; i < vfmig->max_vfs; i++) {
		struct mlx5_vfmig_vf_load *load = vfmig->pending_load[i];

		if (!load)
			continue;
		vfmig->pending_load[i] = NULL;
		clear_bit(i, vfmig->restored);
		mutex_unlock(&vfmig->ctxs_lock);
		mlx5_core_dbg(pf_mdev,
			      "vfmig: dropping unconsumed pending_load for vf %u (vhca_id 0x%04x)\n",
			      i, load->vhca_id);
		vfmig_vf_load_destroy(pf_mdev, load);
		mutex_lock(&vfmig->ctxs_lock);
	}
	mutex_unlock(&vfmig->ctxs_lock);
}

/*
 * Drop all staged LOAD slots from mlx5_device_disable_sriov(): the
 * pending_load array and restored bitmap are indexed by VF id and
 * survive an sriov_numvfs cycle, but the vhca_ids the slots reference do
 * not, so a slot left staged for a torn-down VF generation must not be
 * applied to the next one. No-op on VFs / before pf_init.
 */
void mlx5_vfmig_pf_drop_pending_loads(struct mlx5_core_dev *pf_mdev)
{
	struct mlx5_vfmig_pf *vfmig;

	if (!pf_mdev || mlx5_core_is_vf(pf_mdev))
		return;
	vfmig = pf_mdev->priv.vfmig;
	if (!vfmig)
		return;

	vfmig_pf_get(vfmig);
	down_read(&vfmig->lock);
	if (!vfmig->dead)
		vfmig_drop_pending_loads_locked(vfmig);
	up_read(&vfmig->lock);
	vfmig_pf_put(vfmig);
}

/* Zero every per-VF vf_uuid slot. Caller holds vfmig->lock. */
static void vfmig_drop_vf_uuids_locked(struct mlx5_vfmig_pf *vfmig)
{
	u32 i;

	mutex_lock(&vfmig->ctxs_lock);
	for (i = 0; i < vfmig->max_vfs; i++)
		uuid_copy(&vfmig->vf_uuid[i], &uuid_null);
	mutex_unlock(&vfmig->ctxs_lock);
}

/*
 * Clear all stamped vf_uuids from mlx5_device_disable_sriov(): the
 * vf_uuid array is indexed by VF id and survives an sriov_numvfs cycle,
 * so a tag stamped for one VF generation must not carry over to the next,
 * where a SET_VF_UUID with the next workload's identity would hit the
 * -EBUSY "different UUID already set" guard. No-op on VFs / before
 * pf_init.
 */
void mlx5_vfmig_pf_drop_vf_uuids(struct mlx5_core_dev *pf_mdev)
{
	struct mlx5_vfmig_pf *vfmig;

	if (!pf_mdev || mlx5_core_is_vf(pf_mdev))
		return;
	vfmig = pf_mdev->priv.vfmig;
	if (!vfmig)
		return;

	vfmig_pf_get(vfmig);
	down_read(&vfmig->lock);
	if (!vfmig->dead)
		vfmig_drop_vf_uuids_locked(vfmig);
	up_read(&vfmig->lock);
	vfmig_pf_put(vfmig);
}

/*
 * Detach + free every attached per-VF IOVA domain and clear the array.
 * Caller holds vfmig->lock; ctxs_lock is taken to unpublish each slot,
 * then dropped around the sleepable vfmig_iova_domain_destroy() (which
 * detaches via iommu_detach_device and may take iommu-group locks).
 */
static void vfmig_drop_iova_domains_locked(struct mlx5_vfmig_pf *vfmig)
{
	u32 i;

	mutex_lock(&vfmig->ctxs_lock);
	for (i = 0; i < vfmig->max_vfs; i++) {
		struct vfmig_iova_domain *dom = vfmig->iova_dom[i];

		if (!dom)
			continue;
		vfmig->iova_dom[i] = NULL;
		mutex_unlock(&vfmig->ctxs_lock);
		vfmig_iova_domain_destroy(dom);
		mutex_lock(&vfmig->ctxs_lock);
	}
	mutex_unlock(&vfmig->ctxs_lock);
}

/*
 * Free all per-VF IOVA domains from mlx5_device_disable_sriov(), which
 * runs BEFORE pci_disable_sriov() tears the VFs down. Each domain's fixed
 * IOVA reservation must be released while its VF still exists, so the
 * DMA-IOVA core frees it against the live managed domain rather than
 * leaking the range. The iova_dom array is indexed by VF id and survives
 * an sriov_numvfs cycle, so an arena reserved for one VF generation must
 * not leak into the next. No-op on VFs / before pf_init.
 */
void mlx5_vfmig_pf_drop_iova_domains(struct mlx5_core_dev *pf_mdev)
{
	struct mlx5_vfmig_pf *vfmig;

	if (!pf_mdev || mlx5_core_is_vf(pf_mdev))
		return;
	vfmig = pf_mdev->priv.vfmig;
	if (!vfmig)
		return;

	vfmig_pf_get(vfmig);
	down_read(&vfmig->lock);
	if (!vfmig->dead)
		vfmig_drop_iova_domains_locked(vfmig);
	up_read(&vfmig->lock);
	vfmig_pf_put(vfmig);
}

struct vfmig_iova_domain *
mlx5_vf_get_vfmig_iova_domain(struct mlx5_core_dev *vf_dev)
{
	struct pci_dev *vf_pdev = vf_dev->pdev;
	struct vfmig_iova_domain *dom = NULL;
	struct mlx5_core_dev *pf_mdev;
	struct mlx5_vfmig_pf *vfmig;
	int vf_id;

	if (!vf_pdev || !vf_pdev->is_virtfn)
		return NULL;

	vf_id = pci_iov_vf_id(vf_pdev);
	if (vf_id < 0)
		return NULL;

	pf_mdev = mlx5_vf_get_core_dev(vf_pdev);
	if (!pf_mdev)
		return NULL;

	/*
	 * The PF mdev is pinned by mlx5_vf_get_core_dev() until put, so its
	 * priv.vfmig (and the iova_dom array) stay alive for this read.
	 * iova_dom[vf_id] is published/taken under @ctxs_lock by the
	 * SET_TRACKED handler, so read it under the same lock.
	 *
	 * The returned pointer is used unlocked by the caller (cmd.c, at VF
	 * probe time). That is safe because a tracked VF's domain is only
	 * freed by SET_TRACKED { enable=0 } or SR-IOV teardown, both of which
	 * require the VF to be unbound -- and we are mid-probe of this VF, so
	 * it is bound and the domain cannot be torn down underneath us.
	 */
	vfmig = pf_mdev->priv.vfmig;
	if (vfmig) {
		mutex_lock(&vfmig->ctxs_lock);
		if (vf_id < vfmig->max_vfs)
			dom = vfmig->iova_dom[vf_id];
		mutex_unlock(&vfmig->ctxs_lock);
	}
	mlx5_vf_put_core_dev(pf_mdev);
	return dom;
}

/*
 * Source-side umem placement for a vfmig-tracked VF (header docstring in
 * include/linux/mlx5/driver.h). Backs the ib_core placement hook
 * (ops.umem_place): maps each pinned scatter-gather segment of @sgt into
 * the VFMIG_SLOT_USER_PAGE window via vfmig_iova_user_page_map_phys(),
 * recording one external registry entry per segment, and fills
 * sg_dma_address()/sg_dma_len() so the umem is device-visible without the
 * default dma-iommu streaming map. A later mlx5_vfmig_retag_user_*()
 * promotes the auto-numbered entries to a stable (kind, fw_id) identity
 * for SAVE.
 *
 * Mirrors the dma_map_sgtable() contract: on success every segment is
 * mapped and sgt->nents is set to the mapped count; on failure the
 * segments mapped so far are unwound and their DMA fields cleared.
 * Reads vf_dev->cmd.vfmig_iova_dom, the O(1) lockless probe-time load.
 * Callers gate on a tracked VF (ib_device.use_umem_placement), so a
 * NULL domain here is a driver bug (warn + -ENODEV).
 */
int mlx5_vfmig_map_umem(struct mlx5_core_dev *vf_dev, struct sg_table *sgt)
{
	struct vfmig_iova_domain *dom;
	struct scatterlist *s;
	unsigned int i, mapped = 0;
	int err;

	if (WARN_ON_ONCE(!vf_dev || !sgt))
		return -EINVAL;

	dom = vf_dev->cmd.vfmig_iova_dom;
	if (WARN_ON_ONCE(!dom))
		return -ENODEV;

	for_each_sgtable_sg(sgt, s, i) {
		phys_addr_t phys = sg_phys(s);
		unsigned int off = s->offset & ~PAGE_MASK;
		unsigned int len = s->length;
		dma_addr_t iova;

		/*
		 * ib_umem_pin() hands us page-aligned segments; round @phys
		 * down and @len up so a mid-page offset still maps cleanly.
		 * The returned dma_address carries the byte offset back.
		 */
		err = vfmig_iova_user_page_map_phys(dom, phys & PAGE_MASK,
						    PAGE_ALIGN(len + off),
						    GFP_KERNEL, &iova);
		if (err)
			goto err_undo;

		sg_dma_address(s) = iova + off;
		sg_dma_len(s)	  = len;
		mapped++;
	}

	sgt->nents = mapped;
	return 0;

err_undo:
	for_each_sg(sgt->sgl, s, mapped, i) {
		dma_addr_t iova = sg_dma_address(s);
		unsigned int off = iova & ~PAGE_MASK;
		unsigned int len = sg_dma_len(s);

		(void)vfmig_iova_user_page_unmap_phys(dom, iova - off,
						      PAGE_ALIGN(len + off));
		sg_dma_address(s) = 0;
		sg_dma_len(s)	  = 0;
	}
	return err;
}
EXPORT_SYMBOL(mlx5_vfmig_map_umem);

/*
 * Reverse of mlx5_vfmig_map_umem() (header docstring in
 * include/linux/mlx5/driver.h). Backs the ib_core placement hook
 * (ops.umem_unplace): unlinks every USER_PAGE segment of @sgt from the
 * arena via vfmig_iova_user_page_unmap_phys(), drops its external
 * registry entry, and zeroes sg_dma_address()/sg_dma_len() so the core's
 * subsequent page unpin sees a clean sgt. Segments never mapped (iova ==
 * 0 && len == 0, e.g. after a partial map that already unwound) are
 * skipped.
 */
void mlx5_vfmig_unmap_umem(struct mlx5_core_dev *vf_dev, struct sg_table *sgt)
{
	struct vfmig_iova_domain *dom;
	struct scatterlist *s;
	unsigned int i;

	if (WARN_ON_ONCE(!vf_dev || !sgt))
		return;

	dom = vf_dev->cmd.vfmig_iova_dom;
	if (WARN_ON_ONCE(!dom))
		return;

	for_each_sgtable_sg(sgt, s, i) {
		dma_addr_t iova = sg_dma_address(s);
		unsigned int len = sg_dma_len(s);
		unsigned int off;

		if (!iova && !len)
			continue;

		off = iova & ~PAGE_MASK;
		(void)vfmig_iova_user_page_unmap_phys(dom, iova - off,
						      PAGE_ALIGN(len + off));
		sg_dma_address(s) = 0;
		sg_dma_len(s)	  = 0;
	}
}
EXPORT_SYMBOL(mlx5_vfmig_unmap_umem);

/*
 * Public Stage-2 source-side retag entry point for the mlx5_ib MR
 * creation path (header docstring in include/linux/mlx5/driver.h).
 *
 * Reads vf_dev->cmd.vfmig_iova_dom directly: an O(1), lockless load set
 * in cmd.c at VF probe time iff the VF was vfmig-tracked, NULL otherwise
 * (PFs, untracked VFs, unbound mdevs). The same NULL test at the mlx5_ib
 * callsite lets non-vfmig deployments skip the iova_base/length compute
 * entirely; the check here is defense-in-depth and how we obtain @dom.
 * The pointer's lifetime is the VF's bound lifetime (cmd.c clears it on
 * cmd-ring free, and SET_TRACKED{disable} is gated to unbound VFs), so a
 * non-NULL read stays valid for this call.
 *
 * -ENOENT (no matching entries: umem took a non-vfmig DMA path) folds to
 * 0. -EEXIST (mkey_index collides with a prior retag) and -EINVAL
 * (misaligned args) propagate so the caller can warn; the MR stays usable
 * for data path, just not CRIU-restorable.
 */
int mlx5_vfmig_retag_user_mr(struct mlx5_core_dev *vf_dev, u32 mkey_index,
			     dma_addr_t iova_base, size_t length)
{
	struct vfmig_iova_domain *dom;
	u64 instance_key;
	int err;

	if (!vf_dev)
		return 0;

	dom = vf_dev->cmd.vfmig_iova_dom;
	if (!dom)
		return 0;

	instance_key = VFMIG_HUOBJ_KEY(VFMIG_HUOBJ_KIND_MR, mkey_index);
	err = vfmig_iova_retag_external_range(dom, iova_base, length,
					      instance_key);
	if (err == -ENOENT)
		return 0;
	return err;
}
EXPORT_SYMBOL(mlx5_vfmig_retag_user_mr);

/* Kernel-object helpers; documented in include/linux/mlx5/driver.h. */
int mlx5_vfmig_kobj_record(struct mlx5_core_dev *vf_dev,
			   enum mlx5_vfmig_kobj_kind kind, u32 key, u32 id)
{
	struct vfmig_iova_domain *dom = vf_dev->cmd.vfmig_iova_dom;

	if (!dom)
		return 0;
	return vfmig_iova_kobj_set(dom, kind, key, id);
}
EXPORT_SYMBOL(mlx5_vfmig_kobj_record);

void mlx5_vfmig_kobj_forget(struct mlx5_core_dev *vf_dev,
			    enum mlx5_vfmig_kobj_kind kind, u32 key, u32 id)
{
	vfmig_iova_kobj_clear(vf_dev->cmd.vfmig_iova_dom, kind, key, id);
}
EXPORT_SYMBOL(mlx5_vfmig_kobj_forget);

int mlx5_vfmig_kobj_take(struct mlx5_core_dev *vf_dev,
			 enum mlx5_vfmig_kobj_kind kind, u32 key, u32 *id)
{
	struct vfmig_iova_domain *dom = vf_dev->cmd.vfmig_iova_dom;

	if (!dom || !mlx5_vf_is_restored(vf_dev))
		return -ENOENT;
	return vfmig_iova_kobj_take(dom, kind, key, id);
}
EXPORT_SYMBOL(mlx5_vfmig_kobj_take);

/*
 * Public destination-side bind entry point for the mlx5_ib RESTORE_MR
 * verb body. Header docstring lives in include/linux/mlx5/driver.h.
 *
 * Unlike the retag family (which no-ops with 0 on a non-vfmig
 * deployment), bind is a hard "vfmig is here, the placeholder exists,
 * bind the umem to it" operation: the caller has already gated on
 * vfmig_restore_mode + a tracked-VF ucontext and needs the bind to
 * land, so a NULL vfmig_iova_dom surfaces as -ENODEV rather than a
 * silent no-op that would leave the umem un-bound and the placeholder
 * dangling.
 */
int mlx5_vfmig_bind_user_mr(struct mlx5_core_dev *vf_dev, u32 mkey_index,
			    struct sg_table *sgt)
{
	struct vfmig_iova_domain *dom;

	if (!vf_dev || !sgt)
		return -EINVAL;
	if (mkey_index == 0 || (mkey_index & ~0xffffffU))
		return -EINVAL;

	dom = vf_dev->cmd.vfmig_iova_dom;
	if (!dom)
		return -ENODEV;

	return vfmig_iova_bind_user_object(dom, VFMIG_HUOBJ_KIND_MR,
					   (u64)mkey_index, sgt);
}
EXPORT_SYMBOL(mlx5_vfmig_bind_user_mr);

/*
 * Public destination-side bind entry point for the mlx5_ib RESTORE_CQ
 * verb body's CQE-ring umem. Header docstring lives in
 * include/linux/mlx5/driver.h.
 *
 * Identical shape and error semantics as mlx5_vfmig_bind_user_mr modulo
 * the kind enum. The instance_key is VFMIG_HUOBJ_KEY(KIND_CQ, cqn); the
 * source-side retag (mlx5_vfmig_retag_user_cq, fired from
 * mlx5_ib_create_cq post-FW-create) installed the matching placeholder
 * in the SAVE-side IOVA domain, which LOAD_VHCA_STATE replays onto the
 * destination ahead of this bind.
 */
int mlx5_vfmig_bind_user_cq(struct mlx5_core_dev *vf_dev, u32 cqn,
			    struct sg_table *sgt)
{
	struct vfmig_iova_domain *dom;

	if (!vf_dev || !sgt)
		return -EINVAL;
	if (cqn == 0 || (cqn & ~0xffffffU))
		return -EINVAL;

	dom = vf_dev->cmd.vfmig_iova_dom;
	if (!dom)
		return -ENODEV;

	return vfmig_iova_bind_user_object(dom, VFMIG_HUOBJ_KIND_CQ,
					   (u64)cqn, sgt);
}
EXPORT_SYMBOL(mlx5_vfmig_bind_user_cq);

/*
 * Public destination-side bind entry point for the mlx5_ib RESTORE_QP
 * verb body's WQ-ring umem. Header docstring lives in
 * include/linux/mlx5/driver.h.
 *
 * Identical shape and error semantics as mlx5_vfmig_bind_user_cq modulo
 * the kind enum. The instance_key is VFMIG_HUOBJ_KEY(KIND_QP, qpn); the
 * source-side retag (mlx5_vfmig_retag_user_qp, fired from create_user_qp
 * post-FW-create) installed the matching placeholder in the SAVE-side
 * IOVA domain, which LOAD_VHCA_STATE replays onto the destination ahead
 * of this bind.
 */
int mlx5_vfmig_bind_user_qp(struct mlx5_core_dev *vf_dev, u32 qpn,
			    struct sg_table *sgt)
{
	struct vfmig_iova_domain *dom;

	if (!vf_dev || !sgt)
		return -EINVAL;
	if (qpn == 0 || (qpn & ~0xffffffU))
		return -EINVAL;

	dom = vf_dev->cmd.vfmig_iova_dom;
	if (!dom)
		return -ENODEV;

	return vfmig_iova_bind_user_object(dom, VFMIG_HUOBJ_KIND_QP,
					   (u64)qpn, sgt);
}
EXPORT_SYMBOL(mlx5_vfmig_bind_user_qp);

/*
 * Public destination-side bind entry point for the doorbell-page umem
 * of the mlx5_ib RESTORE_CQ / RESTORE_QP / RESTORE_SRQ verb bodies.
 * Header docstring lives in include/linux/mlx5/driver.h.
 *
 * The instance_key is VFMIG_HUOBJ_KEY(KIND_DBR, user_virt & PAGE_MASK)
 * -- DBR is the only kind whose fw_id is a userspace virtual address
 * rather than a FW-allocated identifier (no FW resource owns "the
 * doorbell page"; the FW only sees the DMA address of individual 8-byte
 * doorbell records inside it). mlx5_ib_db_map_user already dedups on
 * (mm, user_virt & PAGE_MASK), so both the SAVE-side
 * mlx5_vfmig_retag_user_dbr and this bind lean on that key. @user_virt
 * need not be page-aligned: it is masked to PAGE_MASK here.
 *
 * One extra invariant over mlx5_vfmig_bind_user_mr: @sgt must describe
 * exactly one PAGE_SIZE entry, since mlx5_ib_db_map_user pins a single
 * page per doorbell umem. Multi-page sgts are rejected with -EINVAL.
 */
int mlx5_vfmig_bind_user_dbr(struct mlx5_core_dev *vf_dev,
			     unsigned long user_virt, struct sg_table *sgt)
{
	struct vfmig_iova_domain *dom;

	if (!vf_dev || !sgt)
		return -EINVAL;
	if (sgt->nents != 1 || sg_dma_len(sgt->sgl) > PAGE_SIZE)
		return -EINVAL;
	if (sgt->sgl->length != PAGE_SIZE)
		return -EINVAL;

	dom = vf_dev->cmd.vfmig_iova_dom;
	if (!dom)
		return -ENODEV;

	return vfmig_iova_bind_user_object(dom, VFMIG_HUOBJ_KIND_DBR,
					   (u64)(user_virt & PAGE_MASK), sgt);
}
EXPORT_SYMBOL(mlx5_vfmig_bind_user_dbr);

/*
 * Public Stage-2 source-side retag entry point for the mlx5_ib user CQ
 * creation path (header docstring in include/linux/mlx5/driver.h).
 * Identical shape to mlx5_vfmig_retag_user_mr() modulo the kind: a single
 * user umem covers the CQE ring buffer and FW assigns @cqn at
 * mlx5_core_create_cq time, so promote its entries to
 * VFMIG_HUOBJ_KEY(KIND_CQ, cqn). The doorbell page is retagged separately
 * by mlx5_vfmig_retag_user_dbr. Same cmd.vfmig_iova_dom fast path and
 * -ENOENT-to-0 mapping as the MR helper.
 */
int mlx5_vfmig_retag_user_cq(struct mlx5_core_dev *vf_dev, u32 cqn,
			     dma_addr_t iova_base, size_t length)
{
	struct vfmig_iova_domain *dom;
	u64 instance_key;
	int err;

	if (!vf_dev)
		return 0;

	dom = vf_dev->cmd.vfmig_iova_dom;
	if (!dom)
		return 0;

	instance_key = VFMIG_HUOBJ_KEY(VFMIG_HUOBJ_KIND_CQ, cqn);
	err = vfmig_iova_retag_external_range(dom, iova_base, length,
					      instance_key);
	if (err == -ENOENT)
		return 0;
	return err;
}
EXPORT_SYMBOL(mlx5_vfmig_retag_user_cq);

/*
 * Public Stage-2 source-side retag entry point for the mlx5_ib user QP
 * creation path (header docstring in include/linux/mlx5/driver.h).
 * Identical shape to the MR/CQ helpers modulo the kind: a QPC-managed QP
 * (RC / UC / UD) shares one umem covering the SQ and RQ WQE buffers and
 * FW assigns @qpn at mlx5_qpc_create_qp time, so promote its entries to
 * VFMIG_HUOBJ_KEY(KIND_QP, qpn). RAW_PACKET / SOURCE_QPN QPs (split
 * SQ/RQ umems) are skipped at the callsite. The doorbell page is
 * retagged separately by mlx5_vfmig_retag_user_dbr. Same
 * cmd.vfmig_iova_dom fast path and -ENOENT-to-0 mapping as the others.
 */
int mlx5_vfmig_retag_user_qp(struct mlx5_core_dev *vf_dev, u32 qpn,
			     dma_addr_t iova_base, size_t length)
{
	struct vfmig_iova_domain *dom;
	u64 instance_key;
	int err;

	if (!vf_dev)
		return 0;

	dom = vf_dev->cmd.vfmig_iova_dom;
	if (!dom)
		return 0;

	instance_key = VFMIG_HUOBJ_KEY(VFMIG_HUOBJ_KIND_QP, qpn);
	err = vfmig_iova_retag_external_range(dom, iova_base, length,
					      instance_key);
	if (err == -ENOENT)
		return 0;
	return err;
}
EXPORT_SYMBOL(mlx5_vfmig_retag_user_qp);

/*
 * Public Stage-2 source-side retag entry point for the mlx5_ib user SRQ
 * creation path (header docstring in include/linux/mlx5/driver.h). All
 * three user SRQ types (BASIC / XRC / TM) share one umem for the SRQ WQE
 * buffer and FW assigns @srqn at mlx5_cmd_create_srq time, so promote its
 * entries to VFMIG_HUOBJ_KEY(KIND_SRQ, srqn). The doorbell page is
 * retagged separately by mlx5_vfmig_retag_user_dbr. Same
 * cmd.vfmig_iova_dom fast path and -ENOENT-to-0 mapping as the others.
 */
int mlx5_vfmig_retag_user_srq(struct mlx5_core_dev *vf_dev, u32 srqn,
			      dma_addr_t iova_base, size_t length)
{
	struct vfmig_iova_domain *dom;
	u64 instance_key;
	int err;

	if (!vf_dev)
		return 0;

	dom = vf_dev->cmd.vfmig_iova_dom;
	if (!dom)
		return 0;

	instance_key = VFMIG_HUOBJ_KEY(VFMIG_HUOBJ_KIND_SRQ, srqn);
	err = vfmig_iova_retag_external_range(dom, iova_base, length,
					      instance_key);
	if (err == -ENOENT)
		return 0;
	return err;
}
EXPORT_SYMBOL(mlx5_vfmig_retag_user_srq);

/*
 * Public Stage-2 source-side retag entry point for the mlx5_ib user
 * doorbell-page allocation path (header docstring in
 * include/linux/mlx5/driver.h). Differs from the buffer-kind helpers in
 * that the fw_id is a page-aligned userspace virtual address rather than
 * a FW identifier -- doorbell pages have no FW identity, so we key on
 * mlx5_ib_db_map_user()'s own (user_virt & PAGE_MASK) dedup value:
 * VFMIG_HUOBJ_KEY(KIND_DBR, user_virt & PAGE_MASK). @length is always
 * PAGE_SIZE. Same cmd.vfmig_iova_dom fast path and -ENOENT-to-0 mapping
 * as the others.
 */
int mlx5_vfmig_retag_user_dbr(struct mlx5_core_dev *vf_dev,
			      unsigned long user_virt,
			      dma_addr_t iova_base, size_t length)
{
	struct vfmig_iova_domain *dom;
	u64 instance_key;
	int err;

	if (!vf_dev)
		return 0;

	dom = vf_dev->cmd.vfmig_iova_dom;
	if (!dom)
		return 0;

	instance_key = VFMIG_HUOBJ_KEY(VFMIG_HUOBJ_KIND_DBR,
				       user_virt & PAGE_MASK);
	err = vfmig_iova_retag_external_range(dom, iova_base, length,
					      instance_key);
	if (err == -ENOENT)
		return 0;
	return err;
}
EXPORT_SYMBOL(mlx5_vfmig_retag_user_dbr);

int mlx5_vfmig_pf_init(struct mlx5_core_dev *pf_mdev)
{
	struct mlx5_vfmig_pf *vfmig;
	struct device *dev;
	dev_t devt;
	int minor;
	int err;

	if (mlx5_core_is_vf(pf_mdev))
		return 0;

	vfmig = kzalloc(sizeof(*vfmig), GFP_KERNEL);
	if (!vfmig)
		return -ENOMEM;

	kref_init(&vfmig->kref);
	init_rwsem(&vfmig->lock);
	mutex_init(&vfmig->ctxs_lock);
	INIT_LIST_HEAD(&vfmig->save_ctxs);
	INIT_LIST_HEAD(&vfmig->load_ctxs);
	vfmig->pf_mdev = pf_mdev;

	vfmig->max_vfs = pf_mdev->priv.sriov.max_vfs;
	if (vfmig->max_vfs) {
		vfmig->restored = bitmap_zalloc(vfmig->max_vfs, GFP_KERNEL);
		if (!vfmig->restored) {
			err = -ENOMEM;
			goto err_free;
		}
		vfmig->pending_load = kcalloc(vfmig->max_vfs,
					      sizeof(*vfmig->pending_load),
					      GFP_KERNEL);
		if (!vfmig->pending_load) {
			err = -ENOMEM;
			goto err_free;
		}
		vfmig->vf_uuid = kcalloc(vfmig->max_vfs,
					 sizeof(*vfmig->vf_uuid),
					 GFP_KERNEL);
		if (!vfmig->vf_uuid) {
			err = -ENOMEM;
			goto err_free;
		}
		vfmig->iova_dom = kcalloc(vfmig->max_vfs,
					  sizeof(*vfmig->iova_dom),
					  GFP_KERNEL);
		if (!vfmig->iova_dom) {
			err = -ENOMEM;
			goto err_free;
		}
	}

	minor = ida_alloc_max(&mlx5_vfmig_minor_ida,
			      MLX5_VFMIG_MAX_DEVICES - 1, GFP_KERNEL);
	if (minor < 0) {
		err = minor;
		goto err_free;
	}
	vfmig->minor = minor;

	devt = MKDEV(MAJOR(mlx5_vfmig_devt), minor);

	cdev_init(&vfmig->cdev, &mlx5_vfmig_fops);
	vfmig->cdev.owner = THIS_MODULE;
	err = cdev_add(&vfmig->cdev, devt, 1);
	if (err)
		goto err_minor;

	dev = device_create(mlx5_vfmig_class, mlx5_core_dma_dev(pf_mdev),
			    devt, vfmig, "mlx5_vfmig!%s",
			    dev_name(mlx5_core_dma_dev(pf_mdev)));
	if (IS_ERR(dev)) {
		err = PTR_ERR(dev);
		goto err_cdev;
	}

	pf_mdev->priv.vfmig = vfmig;

	return 0;

err_cdev:
	cdev_del(&vfmig->cdev);
err_minor:
	ida_free(&mlx5_vfmig_minor_ida, minor);
err_free:
	mutex_destroy(&vfmig->ctxs_lock);
	bitmap_free(vfmig->restored);
	kfree(vfmig->pending_load);
	kfree(vfmig->vf_uuid);
	kfree(vfmig->iova_dom);
	kfree(vfmig);
	return err;
}

void mlx5_vfmig_pf_cleanup(struct mlx5_core_dev *pf_mdev)
{
	struct mlx5_vfmig_pf *vfmig = pf_mdev->priv.vfmig;
	struct mlx5_vfmig_save_ctx *save_ctx;
	struct mlx5_vfmig_load_ctx *load_ctx;
	dev_t devt;

	if (!vfmig)
		return;

	pf_mdev->priv.vfmig = NULL;

	/*
	 * Neuter the device. Tear down open SAVE/LOAD sessions' firmware
	 * resources (PD/MKEY/DMA) while pf_mdev is still alive; the page
	 * lists themselves are mdev-independent and get freed when each fd
	 * is later closed. The down_write blocks until all in-flight
	 * readers/writers drop their read locks, after which the session
	 * lists are stable.
	 */
	down_write(&vfmig->lock);
	vfmig->dead = true;
	list_for_each_entry(save_ctx, &vfmig->save_ctxs, node)
		vfmig_save_release_resources(save_ctx);
	list_for_each_entry(load_ctx, &vfmig->load_ctxs, node)
		vfmig_load_release_resources(load_ctx);

	/*
	 * Drop any staged-but-unconsumed LOAD slots. These hold PF-tied
	 * firmware resources (PD/MKEY/DMA) that must be released while
	 * pf_mdev is still valid, i.e. before the NULL assignment below.
	 */
	vfmig_drop_pending_loads_locked(vfmig);

	/*
	 * Backstop: any per-VF IOVA domains are normally torn down at the
	 * SR-IOV disable that precedes PF unload (mlx5_sriov_detach ->
	 * mlx5_vfmig_pf_drop_iova_domains), while the VFs are still alive.
	 * Clear here too so a domain never outlives the PF.
	 */
	vfmig_drop_iova_domains_locked(vfmig);

	vfmig->pf_mdev = NULL;
	up_write(&vfmig->lock);

	devt = MKDEV(MAJOR(mlx5_vfmig_devt), vfmig->minor);
	device_destroy(mlx5_vfmig_class, devt);
	cdev_del(&vfmig->cdev);

	vfmig_pf_put(vfmig);
}

int mlx5_vfmig_module_init(void)
{
	int err;

	err = alloc_chrdev_region(&mlx5_vfmig_devt, 0,
				  MLX5_VFMIG_MAX_DEVICES, "mlx5_vfmig");
	if (err)
		return err;

	mlx5_vfmig_class = class_create("mlx5_vfmig");
	if (IS_ERR(mlx5_vfmig_class)) {
		err = PTR_ERR(mlx5_vfmig_class);
		goto err_class;
	}

	return 0;

err_class:
	unregister_chrdev_region(mlx5_vfmig_devt, MLX5_VFMIG_MAX_DEVICES);
	return err;
}

void mlx5_vfmig_module_exit(void)
{
	class_destroy(mlx5_vfmig_class);
	unregister_chrdev_region(mlx5_vfmig_devt, MLX5_VFMIG_MAX_DEVICES);
	ida_destroy(&mlx5_vfmig_minor_ida);
}
