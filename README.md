# Documentação de Uso - idhash ObjectObfuscator

## Visão Geral

A classe `ObjectObfuscator` permite serializar, criptografar e ofuscar objetos Java em uma string segura, e também realizar o processo inverso (descriptografar e desserializar).  
Ideal para proteger dados sensíveis em trânsito ou armazenamento.
Ou seja, há uma criptografia simétrica.

---

## Requisitos

- Defina a variável de ambiente `APP_ENCRYPTION_KEY` com uma chave AES de 16, 24 ou 32 bytes.
- Adicione o JAR da lib ao seu projeto e declare a dependência no `pom.xml`.

Obs.: lembrando que no java utilizando UTF-8 cada letra contém 2bytes.

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

### 2. Serializar e criptografar um objeto

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

## Observações

- Se a variável `APP_ENCRYPTION_KEY` não estiver definida ou for inválida, será lançada uma exceção.
- O algoritmo utilizado é AES/CBC/PKCS5Padding.
- O objeto é convertido para JSON antes da criptografia (usa Gson).

---

## API

```java
public static <T> String encode(T object)
public static <T> T decode(String encodedString, Class<T> classOfT)
```

---

## Exemplo Completo

```java
import idhash.ObjectObfuscator;

public class Main {
    public static void main(String[] args) {
        Pessoa pessoa = new Pessoa("João", 30);
        String ofuscado = ObjectObfuscator.encode(pessoa);

        System.out.println("String segura: " + ofuscado);

        Pessoa recuperada = ObjectObfuscator.decode(ofuscado, Pessoa.class);
        System.out.println("Nome: " + recuperada.getNome());
    }
}
```

---

## Segurança

- Nunca compartilhe sua chave de criptografia.
- Use uma chave forte e mantenha-a protegida.

---
