#ifndef _XEN_VPCI_H_
#define _XEN_VPCI_H_

#ifdef CONFIG_HAS_VPCI

#include <xen/pci.h>
#include <xen/types.h>
#include <xen/list.h>

typedef uint32_t vpci_read_t(const struct pci_dev *pdev, unsigned int reg,
                             void *data);

typedef void vpci_write_t(const struct pci_dev *pdev, unsigned int reg,
                          uint32_t val, void *data);

typedef struct {
    unsigned int id;
    bool is_ext;
    int (* init)(struct pci_dev *pdev);
    int (* cleanup)(const struct pci_dev *pdev);
} vpci_capability_t;

#define VPCI_ECAM_BDF(addr)     (((addr) & 0x0ffff000) >> 12)

/*
 * Maximum number of devices supported by the virtual bus topology:
 * each PCI bus supports 32 devices/slots at max or up to 256 when
 * there are multi-function ones which are not yet supported.
 * This limit implies only segment 0, bus 0 is supported.
 */
#define VPCI_MAX_VIRT_DEV       (PCI_SLOT(~0) + 1)

#define REGISTER_VPCI_CAPABILITY(cap, name, finit, fclean, ext) \
    static const vpci_capability_t name##_entry \
        __used_section(".data.rel.ro.vpci") = { \
        .id = (cap), \
        .init = (finit), \
        .cleanup = (fclean), \
        .is_ext = (ext), \
    }

#define REGISTER_VPCI_CAP(name, finit, fclean) \
    REGISTER_VPCI_CAPABILITY(PCI_CAP_ID_##name, name, finit, fclean, false)
#define REGISTER_VPCI_EXTCAP(name, finit, fclean) \
    REGISTER_VPCI_CAPABILITY(PCI_EXT_CAP_ID_##name, name, finit, fclean, true)

int __must_check vpci_init_header(struct pci_dev *pdev);

/* Assign vPCI to device by adding handlers. */
int __must_check vpci_assign_device(struct pci_dev *pdev);

/* Remove all handlers and free vpci related structures. */
void vpci_deassign_device(struct pci_dev *pdev);

/* Add/remove a register handler. */
int __must_check vpci_add_register_mask(struct vpci *vpci,
                                        vpci_read_t *read_handler,
                                        vpci_write_t *write_handler,
                                        unsigned int offset, unsigned int size,
                                        void *data, uint32_t ro_mask,
                                        uint32_t rw1c_mask, uint32_t rsvdp_mask,
                                        uint32_t rsvdz_mask);
static inline int __must_check vpci_add_register(struct vpci *vpci,
                                                 vpci_read_t *read_handler,
                                                 vpci_write_t *write_handler,
                                                 unsigned int offset,
                                                 unsigned int size, void *data)
{
    return vpci_add_register_mask(vpci, read_handler, write_handler, offset,
                                  size, data, 0, 0, 0, 0);
}

int __must_check vpci_remove_register(struct vpci *vpci, unsigned int offset,
                                      unsigned int size);

/* Generic read/write handlers for the PCI config space. */
uint32_t vpci_read(pci_sbdf_t sbdf, unsigned int reg, unsigned int size);
void vpci_write(pci_sbdf_t sbdf, unsigned int reg, unsigned int size,
                uint32_t data);

/* Helper to return the value passed in data. */
uint32_t cf_check vpci_read_val(
    const struct pci_dev *pdev, unsigned int reg, void *data);

/* Passthrough handlers. */
uint32_t cf_check vpci_hw_read8(
    const struct pci_dev *pdev, unsigned int reg, void *data);
uint32_t cf_check vpci_hw_read16(
    const struct pci_dev *pdev, unsigned int reg, void *data);
uint32_t cf_check vpci_hw_read32(
    const struct pci_dev *pdev, unsigned int reg, void *data);
void cf_check vpci_hw_write8(
    const struct pci_dev *pdev, unsigned int reg, uint32_t val, void *data);
void cf_check vpci_hw_write16(
    const struct pci_dev *pdev, unsigned int reg, uint32_t val, void *data);

/*
 * Check for pending vPCI operations on this vcpu. Returns true if the vcpu
 * should not run.
 */
bool __must_check vpci_process_pending(struct vcpu *v);

struct vpci {
    /* List of vPCI handlers for a device. */
    struct list_head handlers;
    spinlock_t lock;

#ifdef __XEN__
    /* Hide the rest of the vpci struct from the user-space test harness. */
    struct vpci_header {
        /* Information about the PCI BARs of this device. */
        struct vpci_bar {
            /* Physical (host) address. */
            uint64_t addr;
            /* Guest address. */
            uint64_t guest_addr;
            uint64_t size;
            uint64_t resizable_sizes;
            struct rangeset *mem;
            enum {
                VPCI_BAR_EMPTY,
                VPCI_BAR_IO,
                VPCI_BAR_MEM32,
                VPCI_BAR_MEM64_LO,
                VPCI_BAR_MEM64_HI,
                VPCI_BAR_ROM,
            } type;
            bool prefetchable : 1;
            /* Store whether the BAR is mapped into guest p2m. */
            bool enabled      : 1;
        } bars[PCI_HEADER_NORMAL_NR_BARS + 1];
        /* At most 6 BARS + 1 expansion ROM BAR. */

        /* Guest (domU only) view of the PCI_COMMAND register. */
        uint16_t guest_cmd;

        /*
         * Store whether the ROM enable bit is set (doesn't imply ROM BAR
         * is mapped into guest p2m) if there's a ROM BAR on the device.
         */
        bool rom_enabled      : 1;
        /*
         * Cache whether memory decoding is enabled from our PoV.
         * Some devices have a sticky memory decoding so that can't be relied
         * upon to know whether BARs are mapped into the guest p2m.
         */
        bool bars_mapped      : 1;
        /* FIXME: currently there's no support for SR-IOV. */
    } header;

    /* MSI data. */
    struct vpci_msi {
      /* Address. */
        uint64_t address;
        /* Mask bitfield. */
        uint32_t mask;
        /* Data. */
        uint16_t data;
        /* Number of vectors configured. */
        uint8_t vectors     : 6;
        /* Supports per-vector masking? */
        bool masking        : 1;
        /* 64-bit address capable? */
        bool address64      : 1;
        /* Enabled? */
        bool enabled        : 1;
        /* Arch-specific data. */
        struct vpci_arch_msi arch;
    } *msi;

    /* MSI-X data. */
    struct vpci_msix {
        struct pci_dev *pdev;
        /* List link. */
        struct list_head next;
        /* Table information. */
#define VPCI_MSIX_TABLE     0
#define VPCI_MSIX_PBA       1
#define VPCI_MSIX_MEM_NUM   2
        uint32_t tables[VPCI_MSIX_MEM_NUM];
        /* Maximum number of vectors supported by the device. */
        uint16_t max_entries : 12;
        /* MSI-X enabled? */
        bool enabled         : 1;
        /* Masked? */
        bool masked          : 1;
        /* Partial table map. */
#define VPCI_MSIX_TBL_HEAD 0
#define VPCI_MSIX_TBL_TAIL 1
#define VPCI_MSIX_PBA_HEAD 2
#define VPCI_MSIX_PBA_TAIL 3
        void __iomem *table[4];
        /* Entries. */
        struct vpci_msix_entry {
            uint64_t addr;
            uint32_t data;
            bool masked  : 1;
            bool updated : 1;
            struct vpci_arch_msix_entry arch;
        } entries[];
    } *msix;
#ifdef CONFIG_HAS_VPCI_GUEST_SUPPORT
    /* Guest SBDF of the device. */
#define INVALID_GUEST_SBDF ((pci_sbdf_t){ .sbdf = ~0U })
    pci_sbdf_t guest_sbdf;
#endif
#endif
};

struct vpci_vcpu {
    /* Per-vcpu structure to store state while {un}mapping of PCI BARs. */
    const struct pci_dev *pdev;
    uint16_t cmd;
    bool rom_only : 1;
};

#ifdef __XEN__
void vpci_dump_msi(void);

/* Make sure there's a hole in the p2m for the MSIX mmio areas. */
int vpci_make_msix_hole(const struct pci_dev *pdev);

/* Arch-specific vPCI MSI helpers. */
void vpci_msi_arch_mask(struct vpci_msi *msi, const struct pci_dev *pdev,
                        unsigned int entry, bool mask);
int __must_check vpci_msi_arch_enable(struct vpci_msi *msi,
                                      const struct pci_dev *pdev,
                                      unsigned int vectors);
void vpci_msi_arch_disable(struct vpci_msi *msi, const struct pci_dev *pdev);
void vpci_msi_arch_update(struct vpci_msi *msi, const struct pci_dev *pdev);
void vpci_msi_arch_init(struct vpci_msi *msi);
void vpci_msi_arch_print(const struct vpci_msi *msi);

/* Arch-specific vPCI MSI-X helpers. */
void vpci_msix_arch_mask_entry(struct vpci_msix_entry *entry,
                               const struct pci_dev *pdev, bool mask);
int __must_check vpci_msix_arch_enable_entry(struct vpci_msix_entry *entry,
                                             const struct pci_dev *pdev,
                                             paddr_t table_base);
int __must_check vpci_msix_arch_disable_entry(struct vpci_msix_entry *entry,
                                              const struct pci_dev *pdev);
void vpci_msix_arch_init_entry(struct vpci_msix_entry *entry);
int vpci_msix_arch_print(const struct vpci_msix *msix);

/*
 * Helper functions to fetch MSIX related data. They are used by both the
 * emulated MSIX code and the BAR handlers.
 */
static inline paddr_t vmsix_table_host_base(const struct vpci *vpci,
                                            unsigned int nr)
{
    return vpci->header.bars[vpci->msix->tables[nr] & PCI_MSIX_BIRMASK].addr;
}

static inline paddr_t vmsix_table_host_addr(const struct vpci *vpci,
                                            unsigned int nr)
{
    return vmsix_table_host_base(vpci, nr) +
           (vpci->msix->tables[nr] & ~PCI_MSIX_BIRMASK);
}

static inline paddr_t vmsix_table_base(const struct vpci *vpci, unsigned int nr)
{
    return vpci->header.bars[vpci->msix->tables[nr] &
                             PCI_MSIX_BIRMASK].guest_addr;
}

static inline paddr_t vmsix_table_addr(const struct vpci *vpci, unsigned int nr)
{
    return vmsix_table_base(vpci, nr) +
           (vpci->msix->tables[nr] & ~PCI_MSIX_BIRMASK);
}

/*
 * Note regarding the size calculation of the PBA: the spec mentions "The last
 * QWORD will not necessarily be fully populated", so it implies that the PBA
 * size is 64-bit aligned.
 */
static inline size_t vmsix_table_size(const struct vpci *vpci, unsigned int nr)
{
    return
        (nr == VPCI_MSIX_TABLE) ? vpci->msix->max_entries * PCI_MSIX_ENTRY_SIZE
                                : ROUNDUP(DIV_ROUND_UP(vpci->msix->max_entries,
                                                       8), 8);
}

static inline unsigned int vmsix_entry_nr(const struct vpci_msix *msix,
                                          const struct vpci_msix_entry *entry)
{
    return entry - msix->entries;
}

bool vpci_access_allowed(unsigned int reg, unsigned int len);

/* ECAM mmio read/write helpers */
bool vpci_ecam_write(pci_sbdf_t sbdf, unsigned int reg, unsigned int len,
                     unsigned long data);

bool vpci_ecam_read(pci_sbdf_t sbdf, unsigned int reg, unsigned int len,
                    unsigned long *data);

#endif /* __XEN__ */

#else /* !CONFIG_HAS_VPCI */
struct vpci_vcpu {};

static inline int vpci_assign_device(struct pci_dev *pdev)
{
    return 0;
}

static inline void vpci_deassign_device(struct pci_dev *pdev) { }

static inline void vpci_dump_msi(void) { }

static inline uint32_t vpci_read(pci_sbdf_t sbdf, unsigned int reg,
                                 unsigned int size)
{
    ASSERT_UNREACHABLE();
    return ~(uint32_t)0;
}

static inline void vpci_write(pci_sbdf_t sbdf, unsigned int reg,
                              unsigned int size, uint32_t data)
{
    ASSERT_UNREACHABLE();
}

static inline bool __must_check vpci_process_pending(struct vcpu *v)
{
    ASSERT_UNREACHABLE();
    return false;
}
#endif

static inline int __must_check vpci_reset_device(struct pci_dev *pdev)
{
    vpci_deassign_device(pdev);
    return vpci_assign_device(pdev);
}

#endif

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
