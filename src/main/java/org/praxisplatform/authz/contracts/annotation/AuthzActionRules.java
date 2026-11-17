package org.praxisplatform.authz.contracts.annotation;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Repeatable container annotation for multiple {@link AuthzActionRule} declarations.
 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface AuthzActionRules {

    /**
     * Declared action or surface rules.
     *
     * @return array of {@link AuthzActionRule} annotations
     */
    AuthzActionRule[] value();
}
