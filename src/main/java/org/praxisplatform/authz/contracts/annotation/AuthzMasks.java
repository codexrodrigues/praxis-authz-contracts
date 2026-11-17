package org.praxisplatform.authz.contracts.annotation;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Repeatable container annotation for multiple {@link AuthzMask} declarations.
 */
@Target({ElementType.FIELD, ElementType.METHOD, ElementType.RECORD_COMPONENT, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface AuthzMasks {

    /**
     * Declared masking rules.
     *
     * @return array of {@link AuthzMask} annotations
     */
    AuthzMask[] value();
}
