package idhash;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;
import java.util.StringTokenizer;

/**
 * Separa a responsabilidade de reflexão (descobrir campos anotados
 * com @ResourceId,
 * concatenar/parsear valores e setar campos) do ObjectObfuscator.
 */
public final class ResourceIdProcessor {

    private ResourceIdProcessor() {
    }

    public static List<Field> obterCamposId(Class<?> clazz) {
        List<Field> idFields = new ArrayList<>();
        Class<?> superClass = clazz.getSuperclass();
        if (!superClass.equals(ObjectObfuscator.class)) {
            idFields.addAll(obterCamposId(superClass));
        }
        Field[] attributes = clazz.getDeclaredFields();
        for (Field field : attributes) {
            if (field.getAnnotation(ResourceId.class) != null) {
                idFields.add(field);
            }
        }
        return idFields;
    }

    public static String obterValor(List<Field> idFields, Object referencia) throws IllegalAccessException {
        StringBuilder idConcatenado = new StringBuilder("");
        for (Field field : idFields) {
            field.setAccessible(true);
            Object fieldInstance = field.get(referencia);
            if (fieldInstance instanceof ObjectObfuscator) {
                List<Field> fieldInstanceFields = obterCamposId(fieldInstance.getClass());
                idConcatenado.append(obterValor(fieldInstanceFields, fieldInstance));
            } else {
                if (fieldInstance != null) {
                    idConcatenado.append(fieldInstance.toString());
                } else {
                    throw new IllegalArgumentException("O atributo " + field.getName() + " está null.");
                }
                idConcatenado.append(ObjectObfuscator.TOKEN);
            }
            if (!showValue(field)) {
                field.set(referencia, null);
            }
        }
        return idConcatenado.toString();
    }

    private static boolean showValue(Field field) {
        ResourceId lResourceId = field.getAnnotation(ResourceId.class);
        if (lResourceId != null) {
            return lResourceId.showValue();
        }
        return false;
    }

    public static void atribuirValor(List<Field> fields, StringTokenizer st, Object referencia) throws Exception {
        for (Field field : fields) {
            field.setAccessible(true);
            if (st == null) {
                if (ObjectObfuscator.class.isAssignableFrom(field.getType())) {
                    ((ObjectObfuscator) field.get(referencia)).decode();
                }
            } else if (ObjectObfuscator.class.isAssignableFrom(field.getType())) {
                Object fieldInstance = field.get(referencia);
                if (fieldInstance == null) {
                    fieldInstance = field.getType().getDeclaredConstructor().newInstance();
                }
                List<Field> fieldInstanceFields = obterCamposId(fieldInstance.getClass());
                atribuirValor(fieldInstanceFields, st, fieldInstance);
                field.set(referencia, fieldInstance);
            } else {
                field.set(referencia, parseId(field, st.nextElement().toString()));
            }
        }
    }

    private static Object parseId(Field field, String value) {
        if ("[NULL_ID]".equals(value)) {
            throw new IllegalArgumentException("O atributo " + field.getName() + " está null.");
        }
        if (field.getType().equals(Integer.class)) {
            return Integer.parseInt(value);
        }
        if (field.getType().equals(Long.class)) {
            return Long.parseLong(value);
        }
        if (field.getType().equals(Byte.class)) {
            return (byte) Integer.parseInt(value);
        }
        if (field.getType().equals(java.math.BigInteger.class)) {
            return new java.math.BigInteger(value);
        }
        if (field.getType().equals(java.math.BigDecimal.class)) {
            return new java.math.BigDecimal(value);
        }
        return value;
    }
}
