/* SPDX-License-Identifier: GPL-2.0 */
/*
 * hwp.c cpufreq driver to run Intel Hardware P-States (HWP)
 *
 * Copyright (C) 2021 Jason Andryuk <jandryuk@gmail.com>
 */

#include <xen/cpumask.h>
#include <xen/init.h>
#include <xen/param.h>
#include <xen/xmalloc.h>
#include <asm/io.h>
#include <asm/msr.h>
#include <acpi/cpufreq/cpufreq.h>

static bool feature_hwp;
static bool feature_hwp_notification;
static bool feature_hwp_activity_window;
static bool feature_hwp_energy_perf;
static bool feature_hwp_pkg_level_ctl;
static bool feature_hwp_peci;

static bool feature_hdc;

__initdata bool opt_cpufreq_hwp = true;
__initdata bool opt_cpufreq_hdc = true;

#define HWP_ENERGY_PERF_MAX_PERFORMANCE 0
#define HWP_ENERGY_PERF_BALANCE         0x80
#define HWP_ENERGY_PERF_MAX_POWERSAVE   0xff
#define IA32_ENERGY_BIAS_BALANCE        0x7
#define IA32_ENERGY_BIAS_MAX_POWERSAVE  0xf
#define IA32_ENERGY_BIAS_MASK           0xf

union hwp_request
{
    struct
    {
        uint64_t min_perf:8;
        uint64_t max_perf:8;
        uint64_t desired:8;
        uint64_t energy_perf:8;
        uint64_t activity_window:10;
        uint64_t package_control:1;
        uint64_t reserved:16;
        uint64_t activity_window_valid:1;
        uint64_t energy_perf_valid:1;
        uint64_t desired_valid:1;
        uint64_t max_perf_valid:1;
        uint64_t min_perf_valid:1;
    };
    uint64_t raw;
};

struct hwp_drv_data
{
    union
    {
        uint64_t hwp_caps;
        struct
        {
            uint64_t highest:8;
            uint64_t guaranteed:8;
            uint64_t most_efficient:8;
            uint64_t lowest:8;
            uint64_t reserved:32;
        } hw;
    };
    union hwp_request curr_req;
    uint16_t activity_window;
    uint8_t minimum;
    uint8_t maximum;
    uint8_t desired;
    uint8_t energy_perf;
};
DEFINE_PER_CPU_READ_MOSTLY(struct hwp_drv_data *, hwp_drv_data);

#define hwp_err(...)     printk(XENLOG_ERR __VA_ARGS__)
#define hwp_info(...)    printk(XENLOG_INFO __VA_ARGS__)
#define hwp_verbose(...)                   \
({                                         \
    if ( cpufreq_verbose )                 \
        printk(XENLOG_DEBUG __VA_ARGS__);  \
})

static int cf_check hwp_governor(struct cpufreq_policy *policy,
                                 unsigned int event)
{
    int ret;

    if ( policy == NULL )
        return -EINVAL;

    switch ( event )
    {
    case CPUFREQ_GOV_START:
    case CPUFREQ_GOV_LIMITS:
        ret = 0;
        break;

    case CPUFREQ_GOV_STOP:
    default:
        ret = -EINVAL;
        break;
    }

    return ret;
}

static struct cpufreq_governor hwp_cpufreq_governor =
{
    .name          = XEN_HWP_GOVERNOR,
    .governor      = hwp_governor,
};

static int __init cf_check cpufreq_gov_hwp_init(void)
{
    return cpufreq_register_governor(&hwp_cpufreq_governor);
}
__initcall(cpufreq_gov_hwp_init);

bool __init hwp_available(void)
{
    unsigned int eax, ecx, unused;
    bool use_hwp;

    if ( boot_cpu_data.cpuid_level < CPUID_PM_LEAF )
    {
        hwp_verbose("cpuid_level (%u) lacks HWP support\n",
                    boot_cpu_data.cpuid_level);
        return false;
    }

    if ( boot_cpu_data.cpuid_level < 0x16 )
    {
        hwp_info("HWP disabled: cpuid_level %x < 0x16 lacks CPU freq info\n",
                 boot_cpu_data.cpuid_level);
        return false;
    }

    cpuid(CPUID_PM_LEAF, &eax, &unused, &ecx, &unused);

    if ( !(eax & CPUID6_EAX_HWP_ENERGY_PERFORMANCE_PREFERENCE) &&
         !(ecx & CPUID6_ECX_IA32_ENERGY_PERF_BIAS) )
    {
        hwp_verbose("HWP disabled: No energy/performance preference available");
        return false;
    }

    feature_hwp                 = eax & CPUID6_EAX_HWP;
    feature_hwp_notification    = eax & CPUID6_EAX_HWP_NOTIFICATION;
    feature_hwp_activity_window = eax & CPUID6_EAX_HWP_ACTIVITY_WINDOW;
    feature_hwp_energy_perf     =
        eax & CPUID6_EAX_HWP_ENERGY_PERFORMANCE_PREFERENCE;
    feature_hwp_pkg_level_ctl   = eax & CPUID6_EAX_HWP_PACKAGE_LEVEL_REQUEST;
    feature_hwp_peci            = eax & CPUID6_EAX_HWP_PECI;

    hwp_verbose("HWP: %d notify: %d act-window: %d energy-perf: %d pkg-level: %d peci: %d\n",
                feature_hwp, feature_hwp_notification,
                feature_hwp_activity_window, feature_hwp_energy_perf,
                feature_hwp_pkg_level_ctl, feature_hwp_peci);

    if ( !feature_hwp )
        return false;

    feature_hdc = eax & CPUID6_EAX_HDC;

    hwp_verbose("HWP: Hardware Duty Cycling (HDC) %ssupported%s\n",
                feature_hdc ? "" : "not ",
                feature_hdc ? opt_cpufreq_hdc ? ", enabled" : ", disabled"
                            : "");

    feature_hdc = feature_hdc && opt_cpufreq_hdc;

    hwp_verbose("HWP: HW_FEEDBACK %ssupported\n",
                (eax & CPUID6_EAX_HW_FEEDBACK) ? "" : "not ");

    use_hwp = feature_hwp && opt_cpufreq_hwp;
    cpufreq_governor_internal = use_hwp;

    if ( use_hwp )
        hwp_info("Using HWP for cpufreq\n");

    return use_hwp;
}

static void hdc_set_pkg_hdc_ctl(bool val)
{
    uint64_t msr;

    if ( rdmsr_safe(MSR_IA32_PKG_HDC_CTL, msr) )
    {
        hwp_err("error rdmsr_safe(MSR_IA32_PKG_HDC_CTL)\n");

        return;
    }

    if ( val )
        msr |= IA32_PKG_HDC_CTL_HDC_PKG_ENABLE;
    else
        msr &= ~IA32_PKG_HDC_CTL_HDC_PKG_ENABLE;

    if ( wrmsr_safe(MSR_IA32_PKG_HDC_CTL, msr) )
        hwp_err("error wrmsr_safe(MSR_IA32_PKG_HDC_CTL): %016lx\n", msr);
}

static void hdc_set_pm_ctl1(bool val)
{
    uint64_t msr;

    if ( rdmsr_safe(MSR_IA32_PM_CTL1, msr) )
    {
        hwp_err("error rdmsr_safe(MSR_IA32_PM_CTL1)\n");

        return;
    }

    if ( val )
        msr |= IA32_PM_CTL1_HDC_ALLOW_BLOCK;
    else
        msr &= ~IA32_PM_CTL1_HDC_ALLOW_BLOCK;

    if ( wrmsr_safe(MSR_IA32_PM_CTL1, msr) )
        hwp_err("error wrmsr_safe(MSR_IA32_PM_CTL1): %016lx\n", msr);
}

static void hwp_get_cpu_speeds(struct cpufreq_policy *policy)
{
    uint32_t base_khz, max_khz, bus_khz, edx;

    cpuid(0x16, &base_khz, &max_khz, &bus_khz, &edx);

    /* aperf/mperf scales base. */
    policy->cpuinfo.perf_freq = base_khz * 1000;
    policy->cpuinfo.min_freq = base_khz * 1000;
    policy->cpuinfo.max_freq = max_khz * 1000;
    policy->min = base_khz * 1000;
    policy->max = max_khz * 1000;
    policy->cur = 0;
}

static void cf_check hwp_init_msrs(void *info)
{
    struct cpufreq_policy *policy = info;
    struct hwp_drv_data *data = this_cpu(hwp_drv_data);
    uint64_t val;

    /*
     * Package level MSR, but we don't have a good idea of packages here, so
     * just do it everytime.
     */
    if ( rdmsr_safe(MSR_IA32_PM_ENABLE, val) )
    {
        hwp_err("CPU%u: error rdmsr_safe(MSR_IA32_PM_ENABLE)\n", policy->cpu);
        data->curr_req.raw = -1;
        return;
    }

    /* Ensure we don't generate interrupts */
    if ( feature_hwp_notification )
        wrmsr_safe(MSR_IA32_HWP_INTERRUPT, 0);

    hwp_verbose("CPU%u: MSR_IA32_PM_ENABLE: %016lx\n", policy->cpu, val);
    if ( !(val & IA32_PM_ENABLE_HWP_ENABLE) )
    {
        val |= IA32_PM_ENABLE_HWP_ENABLE;
        if ( wrmsr_safe(MSR_IA32_PM_ENABLE, val) )
        {
            hwp_err("CPU%u: error wrmsr_safe(MSR_IA32_PM_ENABLE, %lx)\n",
                    policy->cpu, val);
            data->curr_req.raw = -1;
            return;
        }
    }

    if ( rdmsr_safe(MSR_IA32_HWP_CAPABILITIES, data->hwp_caps) )
    {
        hwp_err("CPU%u: error rdmsr_safe(MSR_IA32_HWP_CAPABILITIES)\n",
                policy->cpu);
        data->curr_req.raw = -1;
        return;
    }

    if ( rdmsr_safe(MSR_IA32_HWP_REQUEST, data->curr_req.raw) )
    {
        hwp_err("CPU%u: error rdmsr_safe(MSR_IA32_HWP_REQUEST)\n", policy->cpu);
        data->curr_req.raw = -1;
        return;
    }

    if ( !feature_hwp_energy_perf ) {
        if ( rdmsr_safe(MSR_IA32_ENERGY_PERF_BIAS, val) )
        {
            hwp_err("error rdmsr_safe(MSR_IA32_ENERGY_PERF_BIAS)\n");
            data->curr_req.raw = -1;

            return;
        }

        data->energy_perf = val & IA32_ENERGY_BIAS_MASK;
    }

    /*
     * Check for APERF/MPERF support in hardware
     * also check for boost/turbo support
     */
    intel_feature_detect(policy);

    if ( feature_hdc )
    {
        hdc_set_pkg_hdc_ctl(true);
        hdc_set_pm_ctl1(true);
    }

    hwp_get_cpu_speeds(policy);
}

static int cf_check hwp_cpufreq_verify(struct cpufreq_policy *policy)
{
    struct hwp_drv_data *data = per_cpu(hwp_drv_data, policy->cpu);

    if ( !feature_hwp_energy_perf && data->energy_perf )
    {
        if ( data->energy_perf > IA32_ENERGY_BIAS_MAX_POWERSAVE )
        {
            hwp_err("energy_perf %d exceeds IA32_ENERGY_PERF_BIAS range 0-15\n",
                    data->energy_perf);

            return -EINVAL;
        }
    }

    if ( !feature_hwp_activity_window && data->activity_window )
    {
        hwp_err("HWP activity window not supported\n");

        return -EINVAL;
    }

    return 0;
}

/* val 0 - highest performance, 15 - maximum energy savings */
static void hwp_energy_perf_bias(const struct hwp_drv_data *data)
{
    uint64_t msr;
    uint8_t val = data->energy_perf;

    ASSERT(val <= IA32_ENERGY_BIAS_MAX_POWERSAVE);

    if ( rdmsr_safe(MSR_IA32_ENERGY_PERF_BIAS, msr) )
    {
        hwp_err("error rdmsr_safe(MSR_IA32_ENERGY_PERF_BIAS)\n");

        return;
    }

    msr &= ~IA32_ENERGY_BIAS_MASK;
    msr |= val;

    if ( wrmsr_safe(MSR_IA32_ENERGY_PERF_BIAS, msr) )
        hwp_err("error wrmsr_safe(MSR_IA32_ENERGY_PERF_BIAS): %016lx\n", msr);
}

static void cf_check hwp_write_request(void *info)
{
    struct cpufreq_policy *policy = info;
    struct hwp_drv_data *data = this_cpu(hwp_drv_data);
    union hwp_request hwp_req = data->curr_req;

    BUILD_BUG_ON(sizeof(union hwp_request) != sizeof(uint64_t));
    if ( wrmsr_safe(MSR_IA32_HWP_REQUEST, hwp_req.raw) )
    {
        hwp_err("CPU%u: error wrmsr_safe(MSR_IA32_HWP_REQUEST, %lx)\n",
                policy->cpu, hwp_req.raw);
        rdmsr_safe(MSR_IA32_HWP_REQUEST, data->curr_req.raw);
    }

    if ( !feature_hwp_energy_perf )
        hwp_energy_perf_bias(data);

}

static int cf_check hwp_cpufreq_target(struct cpufreq_policy *policy,
                                       unsigned int target_freq,
                                       unsigned int relation)
{
    unsigned int cpu = policy->cpu;
    struct hwp_drv_data *data = per_cpu(hwp_drv_data, cpu);
    /* Zero everything to ensure reserved bits are zero... */
    union hwp_request hwp_req = { .raw = 0 };

    /* .. and update from there */
    hwp_req.min_perf = data->minimum;
    hwp_req.max_perf = data->maximum;
    hwp_req.desired = data->desired;
    if ( feature_hwp_energy_perf )
        hwp_req.energy_perf = data->energy_perf;
    if ( feature_hwp_activity_window )
        hwp_req.activity_window = data->activity_window;

    if ( hwp_req.raw == data->curr_req.raw )
        return 0;

    data->curr_req = hwp_req;

    hwp_verbose("CPU%u: wrmsr HWP_REQUEST %016lx\n", cpu, hwp_req.raw);
    on_selected_cpus(cpumask_of(cpu), hwp_write_request, policy, 1);

    return 0;
}

static int cf_check hwp_cpufreq_cpu_init(struct cpufreq_policy *policy)
{
    unsigned int cpu = policy->cpu;
    struct hwp_drv_data *data;

    data = xzalloc(struct hwp_drv_data);
    if ( !data )
        return -ENOMEM;

    if ( cpufreq_opt_governor )
        printk(XENLOG_WARNING
               "HWP: governor \"%s\" is incompatible with hwp. Using default \"%s\"\n",
               cpufreq_opt_governor->name, hwp_cpufreq_governor.name);
    policy->governor = &hwp_cpufreq_governor;

    per_cpu(hwp_drv_data, cpu) = data;

    on_selected_cpus(cpumask_of(cpu), hwp_init_msrs, policy, 1);

    if ( data->curr_req.raw == -1 )
    {
        hwp_err("CPU%u: Could not initialize HWP properly\n", cpu);
        XFREE(per_cpu(hwp_drv_data, cpu));
        return -ENODEV;
    }

    data->minimum = data->curr_req.min_perf;
    data->maximum = data->curr_req.max_perf;
    data->desired = data->curr_req.desired;
    /* the !feature_hwp_energy_perf case was handled in hwp_init_msrs(). */
    if ( feature_hwp_energy_perf )
        data->energy_perf = data->curr_req.energy_perf;

    hwp_verbose("CPU%u: IA32_HWP_CAPABILITIES: %016lx\n", cpu, data->hwp_caps);

    hwp_verbose("CPU%u: rdmsr HWP_REQUEST %016lx\n", cpu, data->curr_req.raw);

    return 0;
}

static int cf_check hwp_cpufreq_cpu_exit(struct cpufreq_policy *policy)
{
    XFREE(per_cpu(hwp_drv_data, policy->cpu));

    return 0;
}

/*
 * The SDM reads like turbo should be disabled with MSR_IA32_PERF_CTL and
 * PERF_CTL_TURBO_DISENGAGE, but that does not seem to actually work, at least
 * with my HWP testing.  MSR_IA32_MISC_ENABLE and MISC_ENABLE_TURBO_DISENGAGE
 * is what Linux uses and seems to work.
 */
static void cf_check hwp_set_misc_turbo(void *info)
{
    const struct cpufreq_policy *policy = info;
    uint64_t msr;

    if ( rdmsr_safe(MSR_IA32_MISC_ENABLE, msr) )
    {
        hwp_err("CPU%u: error rdmsr_safe(MSR_IA32_MISC_ENABLE)\n", policy->cpu);

        return;
    }

    if ( policy->turbo == CPUFREQ_TURBO_ENABLED )
        msr &= ~MSR_IA32_MISC_ENABLE_TURBO_DISENGAGE;
    else
        msr |= MSR_IA32_MISC_ENABLE_TURBO_DISENGAGE;

    if ( wrmsr_safe(MSR_IA32_MISC_ENABLE, msr) )
        hwp_err("CPU%u: error wrmsr_safe(MSR_IA32_MISC_ENABLE): %016lx\n",
                policy->cpu, msr);
}

static int cf_check hwp_cpufreq_update(int cpuid, struct cpufreq_policy *policy)
{
    on_selected_cpus(cpumask_of(cpuid), hwp_set_misc_turbo, policy, 1);

    return 0;
}

static const struct cpufreq_driver __initconstrel hwp_cpufreq_driver =
{
    .name   = "hwp-cpufreq",
    .verify = hwp_cpufreq_verify,
    .target = hwp_cpufreq_target,
    .init   = hwp_cpufreq_cpu_init,
    .exit   = hwp_cpufreq_cpu_exit,
    .update = hwp_cpufreq_update,
};

int get_hwp_para(const struct cpufreq_policy *policy,
                 struct xen_hwp_para *hwp_para)
{
    unsigned int cpu = policy->cpu;
    const struct hwp_drv_data *data = per_cpu(hwp_drv_data, cpu);

    if ( data == NULL )
        return -EINVAL;

    hwp_para->features        =
        (feature_hwp_activity_window ? XEN_SYSCTL_HWP_FEAT_ACT_WINDOW  : 0) |
        (feature_hwp_energy_perf     ? XEN_SYSCTL_HWP_FEAT_ENERGY_PERF : 0);
    hwp_para->lowest          = data->hw.lowest;
    hwp_para->most_efficient  = data->hw.most_efficient;
    hwp_para->guaranteed      = data->hw.guaranteed;
    hwp_para->highest         = data->hw.highest;
    hwp_para->minimum         = data->minimum;
    hwp_para->maximum         = data->maximum;
    hwp_para->energy_perf     = data->energy_perf;
    hwp_para->activity_window = data->activity_window;
    hwp_para->desired         = data->desired;

    return 0;
}

int set_hwp_para(struct cpufreq_policy *policy,
                 struct xen_set_hwp_para *set_hwp)
{
    unsigned int cpu = policy->cpu;
    struct hwp_drv_data *data = per_cpu(hwp_drv_data, cpu);

    if ( data == NULL )
        return -EINVAL;

    /* Validate all parameters first */
    if ( set_hwp->set_params & ~XEN_SYSCTL_HWP_SET_PARAM_MASK )
        return -EINVAL;

    if ( set_hwp->activity_window & ~XEN_SYSCTL_HWP_ACT_WINDOW_MASK )
        return -EINVAL;

    if ( !feature_hwp_energy_perf &&
         (set_hwp->set_params & XEN_SYSCTL_HWP_SET_ENERGY_PERF) &&
         set_hwp->energy_perf > IA32_ENERGY_BIAS_MAX_POWERSAVE )
        return -EINVAL;

    if ( (set_hwp->set_params & XEN_SYSCTL_HWP_SET_DESIRED) &&
         set_hwp->desired != 0 &&
         (set_hwp->desired < data->hw.lowest ||
          set_hwp->desired > data->hw.highest) )
        return -EINVAL;

    /*
     * minimum & maximum are not validated as hardware doesn't seem to care
     * and the SDM says CPUs will clip internally.
     */

    /* Apply presets */
    switch ( set_hwp->set_params & XEN_SYSCTL_HWP_SET_PRESET_MASK )
    {
    case XEN_SYSCTL_HWP_SET_PRESET_POWERSAVE:
        data->minimum = data->hw.lowest;
        data->maximum = data->hw.lowest;
        data->activity_window = 0;
        if ( feature_hwp_energy_perf )
            data->energy_perf = HWP_ENERGY_PERF_MAX_POWERSAVE;
        else
            data->energy_perf = IA32_ENERGY_BIAS_MAX_POWERSAVE;
        data->desired = 0;
        break;

    case XEN_SYSCTL_HWP_SET_PRESET_PERFORMANCE:
        data->minimum = data->hw.highest;
        data->maximum = data->hw.highest;
        data->activity_window = 0;
        data->energy_perf = HWP_ENERGY_PERF_MAX_PERFORMANCE;
        data->desired = 0;
        break;

    case XEN_SYSCTL_HWP_SET_PRESET_BALANCE:
        data->minimum = data->hw.lowest;
        data->maximum = data->hw.highest;
        data->activity_window = 0;
        if ( feature_hwp_energy_perf )
            data->energy_perf = HWP_ENERGY_PERF_BALANCE;
        else
            data->energy_perf = IA32_ENERGY_BIAS_BALANCE;
        data->desired = 0;
        break;

    case XEN_SYSCTL_HWP_SET_PRESET_NONE:
        break;

    default:
        return -EINVAL;
    }

    /* Further customize presets if needed */
    if ( set_hwp->set_params & XEN_SYSCTL_HWP_SET_MINIMUM )
        data->minimum = set_hwp->minimum;

    if ( set_hwp->set_params & XEN_SYSCTL_HWP_SET_MAXIMUM )
        data->maximum = set_hwp->maximum;

    if ( set_hwp->set_params & XEN_SYSCTL_HWP_SET_ENERGY_PERF )
        data->energy_perf = set_hwp->energy_perf;

    if ( set_hwp->set_params & XEN_SYSCTL_HWP_SET_DESIRED )
        data->desired = set_hwp->desired;

    if ( set_hwp->set_params & XEN_SYSCTL_HWP_SET_ACT_WINDOW )
        data->activity_window = set_hwp->activity_window &
                                XEN_SYSCTL_HWP_ACT_WINDOW_MASK;

    hwp_cpufreq_target(policy, 0, 0);

    return 0;
}

int __init hwp_register_driver(void)
{
    return cpufreq_register_driver(&hwp_cpufreq_driver);
}
