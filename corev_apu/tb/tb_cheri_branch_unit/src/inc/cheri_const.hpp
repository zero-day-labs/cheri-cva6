#ifndef CHERI_LIB_H
#define CHERI_LIB_H
/**
 * @{ \name CHERI ISA Constants.
 */
/**
 * \brief CHERI ISA Constants.
 *
 * The following consts are hardcoded values of exceptions, bits and object types
 * defined in the CHERI ISA
 */
namespace cheri_isa {
    // Capability otype fields constants
    const int UNSEALED_CAP                    = -1;
    const int SENTRY_CAP                      = -2;
    const int MEM_TYPE_TOK_CAP                = -3;
    const int IND_ENT_CAP                     = -4;
    const int SEALED_CAP                      = -17;
    const int OTYPE_MAX                       = -5;

    // Capability hard perms
    const int PERMIT_SET_CID                  = 11;
    const int PERMIT_SYS_REGS                 = 10;
    const int PERMIT_UNSEAL                   = 9;
    const int PERMIT_CINVOKE                  = 8;
    const int PERMIT_SEAL                     = 7;
    const int PERMIT_STORE_LOCAL_CAP          = 6;
    const int PERMIT_STORE_CAP                = 5;
    const int PERMIT_LOAD_CAP                 = 4;
    const int PERMIT_STORE                    = 3;
    const int PERMIT_LOAD                     = 2;
    const int PERMIT_EXECUTE                  = 1;
    const int GLOBAL                          = 0;


    const int CAP_LENGTH_VIOLATION            = 1;
    const int CAP_TAG_VIOLATION               = 2;
    const int CAP_SEAL_VIOLATION              = 3;
    const int CAP_TYPE_VIOLATION              = 4;
    const int CAP_USER_DEF_PERM_VIOLATION     = 8;
    const int CAP_REPRE_VIOLATION             = 10;
    const int CAP_UNLIGNED_BASE               = 11;
    const int CAP_GLOBAL_VIOLATION            = 16;
    const int CAP_PERM_EXEC_VIOLATION         = 17;
    const int CAP_PERM_LD_VIOLATION           = 18;
    const int CAP_PERM_ST_VIOLATION           = 19;
    const int CAP_PERM_LD_CAP_VIOLATION       = 20;
    const int CAP_PERM_ST_CAP_VIOLATION       = 21;
    const int CAP_PERM_ST_CAP_LOCAL_VIOLATION = 22;
    const int CAP_PERM_SEAL                   = 23;
    const int CAP_PERM_ACCESS_SYS_REGS        = 24;
    const int CAP_PERM_CINVOKE                = 25;
    const int CAP_PERM_ACCESS_CINVOKE_IDC     = 26;
    const int CAP_PERM_UNSEAL                 = 27;
    const int CAP_PERM_SET_CID                = 28;

    const int CAP_UPERMS_SHIFT                = 15;
}
/**
 * @}
 */
#endif