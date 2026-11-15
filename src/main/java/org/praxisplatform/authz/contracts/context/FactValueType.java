package org.praxisplatform.authz.contracts.context;

/**
 * Canonical scalar or element value type for facts declared in a {@link FactContract}.
 */
public enum FactValueType {
    STRING,
    INT64,
    DECIMAL,
    BOOLEAN,
    LOCAL_DATE,
    INSTANT,
    ENUM
}
