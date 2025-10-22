package idhash;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Annotation simples para marcar campos que participam do resourceId.
 * Removidas dependências Jackson para evitar exigir essa biblioteca em tempo de
 * compilação do módulo que apenas consome a annotation.
 */
@Target(ElementType.FIELD)
@Retention(RetentionPolicy.RUNTIME)
public @interface ResourceId {
    boolean showValue() default false;
}
