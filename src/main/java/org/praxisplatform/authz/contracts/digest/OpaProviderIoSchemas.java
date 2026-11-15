package org.praxisplatform.authz.contracts.digest;

import java.util.Set;

/**
 * Frozen schema version constants for the OPA provider I/O boundary and compiler profile ({@code CC11},
 * {@code OPA-IO-001}).
 */
public final class OpaProviderIoSchemas {

    public static final String TARGET_INPUT_V1 = "praxis.opa-target-input/v1";
    public static final String TARGET_RESULT_V1 = "praxis.opa-target-result/v1";
    public static final String SEARCH_INPUT_V1 = "praxis.opa-search-input/v1";
    public static final String UCAST_RESULT_V1 = "praxis.opa-ucast-result/v1";
    public static final String COMPILER_PROFILE_V1 = "praxis.rego-compiler-profile/v1";
    public static final String COMBINING_PROFILE_V1 = "praxis.authorization-combining/v1";

    /** Complete set of required OPA provider I/O schemas for V1 compatibility handshakes. */
    public static final Set<String> REQUIRED_PROVIDER_IO_SCHEMAS_V1 = Set.of(
            TARGET_INPUT_V1,
            TARGET_RESULT_V1,
            SEARCH_INPUT_V1,
            UCAST_RESULT_V1
    );

    private OpaProviderIoSchemas() {}
}
