package org.praxisplatform.authz.contracts.envelope;

/**
 * Authority role of a policy contribution in the algebraic combining formula
 * ({@code HardGuard ∩ GrantSurface ∩ Restrictions}, {@code PCB-AUTH-001}, {@code PDP-CMB-004}).
 */
public enum ContributionAuthority {
    GRANT,
    RESTRICT
}
