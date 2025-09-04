# Documentação de Uso - idhash ObjectObfuscator

## Visão Geral

A classe `ObjectObfuscator` permite serializar, criptografar e ofuscar objetos Java em uma string segura, e também realizar o processo inverso (descriptografar e desserializar).  
Ideal para proteger dados sensíveis em trânsito ou armazenamento, utilizando criptografia simétrica (AES).

Além disso, é possível criptografar e descriptografar apenas campos específicos do objeto, utilizando a annotation `@ResourceId` em campos do tipo `String`, `Long`, `Integer`, `BigInteger`, entre outros tipos suportados.

---

## Requisitos

- Defina a variável de ambiente `APP_ENCRYPTION_KEY` com uma chave AES de 16, 24 ou 32 bytes.
- Adicione o JAR da lib ao seu projeto e declare a dependência no `pom.xml`.

Obs.: No Java, utilizando UTF-8, cada caractere pode ocupar mais de 1 byte. Certifique-se do tamanho correto da chave.

## Exemplo de Uso

### 1. Defina a variável de ambiente

No terminal ou no ambiente do servidor:

```sh
export APP_ENCRYPTION_KEY="sua-chave-aqui-16ou24ou32bytes"
```

No Windows:

```cmd
set APP_ENCRYPTION_KEY=sua-chave-aqui-16ou24ou32bytes
```

---

### 2. Serializar e criptografar um objeto inteiro

```java
import idhash.ObjectObfuscator;

Usuario usuario = new Usuario("Maria", "maria@email.com");
String seguro = ObjectObfuscator.encode(usuario);
// seguro agora é uma String criptografada e ofuscada
```

---

### 3. Descriptografar e desserializar

```java
Usuario usuarioOriginal = ObjectObfuscator.decode(seguro, Usuario.class);
```

---

### 4. Criptografar apenas campos anotados com @ResourceId

```java
import idhash.ObjectObfuscator;
import idhash.ResourceId;

public class Usuario {
    @ResourceId
    private Long id;
    @ResourceId
    private String codigo;
    private String nome;
    // getters/setters
}

Usuario usuario = new Usuario();
usuario.setId(123L);
usuario.setCodigo("ABC123");
usuario.setNome("Maria");

// Criptografa apenas os campos anotados
ObjectObfuscator.encodeResourceIds(usuario);

// Descriptografa apenas os campos anotados
ObjectObfuscator.decodeResourceIds(usuario);
```

---

## Observações

- Se a variável `APP_ENCRYPTION_KEY` não estiver definida ou for inválida, será lançada uma exceção.
- O algoritmo utilizado é AES/CBC/PKCS5Padding.
- O objeto é convertido para JSON antes da criptografia (usa Gson).
- Campos anotados com `@ResourceId` podem ser dos tipos: `String`, `Long`, `Integer`, `BigInteger`, entre outros suportados.

---

## API

```java
public static <T> String encode(T object)
public static <T> T decode(String encodedString, Class<T> classOfT)
public static <T> T encodeResourceIds(T object)
public static <T> T decodeResourceIds(T object)
```

---

## Exemplo Completo

```java
import idhash.ObjectObfuscator;
import idhash.ResourceId;

public class Main {
    public static void main(String[] args) {
        Pessoa pessoa = new Pessoa("João", 30);
        String ofuscado = ObjectObfuscator.encode(pessoa);

        System.out.println("String segura: " + ofuscado);

        Pessoa recuperada = ObjectObfuscator.decode(ofuscado, Pessoa.class);
        System.out.println("Nome: " + recuperada.getNome());

        // Exemplo com campos anotados
        pessoa.setId(123L);
        ObjectObfuscator.encodeResourceIds(pessoa);
        ObjectObfuscator.decodeResourceIds(pessoa);
    }
}
```

---

## Segurança

- Nunca compartilhe sua chave de criptografia.
- Use uma chave forte e mantenha-a protegida.
- Recomenda-se utilizar variáveis de ambiente para armazenar a chave.

---
