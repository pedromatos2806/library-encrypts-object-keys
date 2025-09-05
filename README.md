# Documentação de Uso - idhash ObjectObfuscator

## Visão Geral

A classe `ObjectObfuscator` permite criptografar, ofuscar e recuperar IDs de objetos Java, além de serializar e proteger objetos inteiros.  
Ela utiliza criptografia simétrica (AES) e separa os IDs usando um token especial (`|*|`).  
Você pode criptografar e descriptografar campos específicos anotados com `@ResourceId`, suportando tipos como `String`, `Long`, `Integer`, `BigInteger`, `BigDecimal` e outros.

---

## Requisitos

- Defina a variável de ambiente `APP_ENCRYPTION_KEY` com uma chave AES de 16, 24 ou 32 bytes.
- Adicione o JAR da lib ao seu projeto e declare a dependência no `pom.xml`.
- Adicione também a dependência do Apache Commons Lang3 (`org.apache.commons.lang3.StringUtils`).

## Instalação

No Maven:

```xml
<dependency>
    <groupId>org.apache.commons</groupId>
    <artifactId>commons-lang3</artifactId>
    <version>3.14.0</version>
</dependency>
```

---

## Como funciona

### 1. Criptografia de IDs

- Os campos anotados com `@ResourceId` são concatenados em uma única string, separados pelo token `|*|`.
- Essa string é criptografada usando AES e armazenada no campo `resourceId` do objeto.
- Para decodificar, a string é descriptografada e os valores são separados novamente pelo token, sendo convertidos para o tipo original de cada campo.

### 2. Criptografia de objetos inteiros

- O objeto é serializado para JSON e criptografado.
- Pode ser recuperado usando o método de decodificação, informando a classe original.

---

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

### 2. Criptografar e recuperar IDs

```java
import idhash.ObjectObfuscator;
import idhash.ResourceId;
import java.math.BigInteger;

public class Usuario extends ObjectObfuscator {
    @ResourceId
    private Long id;
    @ResourceId
    private String codigo;
    @ResourceId
    private BigInteger numeroGrande;
    private String nome;

    public Usuario(Long id, String codigo, BigInteger numeroGrande, String nome) {
        this.id = id;
        this.codigo = codigo;
        this.numeroGrande = numeroGrande;
        this.nome = nome;
    }
}

// Criptografar os IDs
Usuario usuario = new Usuario(123L, "ABC123", new BigInteger("987654321"), "Maria");
usuario.encode();
String resourceIdCriptografado = usuario.getResourceId();

// Recuperar os IDs originais
Usuario usuarioRestaurado = new Usuario(null, null, null, null);
usuarioRestaurado.setResourceId(resourceIdCriptografado);
usuarioRestaurado.decode();
// Agora os campos id, codigo e numeroGrande estão restaurados
```

---

### 3. Criptografar e recuperar um objeto inteiro

```java
Usuario usuario = new Usuario(123L, "ABC123", new BigInteger("987654321"), "Maria");
String seguro = ObjectObfuscator.encrypt(usuario.toString()); // ou use ObjectObfuscator.encode(usuario) se implementar toJson

// Para recuperar, use:
String original = ObjectObfuscator.decrypt(seguro);
```

---

### 4. Criptografar e recuperar uma string de IDs concatenados

```java
String idsConcatenados = "123|*|ABC123|*|987654321|*|";
String criptografado = ObjectObfuscator.encrypt(idsConcatenados);
String decodificado = ObjectObfuscator.decrypt(criptografado);
// decodificado == idsConcatenados
```

---

## Observações

- Se a variável `APP_ENCRYPTION_KEY` não estiver definida ou for inválida, será lançada uma exceção.
- O algoritmo utilizado é AES/CBC/PKCS5Padding.
- Os campos anotados com `@ResourceId` podem ser dos tipos: `String`, `Long`, `Integer`, `BigInteger`, `BigDecimal`, entre outros suportados.
- O token separador padrão é `|*|`, mas pode ser alterado no código se necessário.

---

## API Principal

```java
public void encode(); // Criptografa os campos anotados e preenche resourceId
public void decode(); // Descriptografa resourceId e restaura os campos anotados

public String getResourceId(); // Retorna o valor criptografado dos IDs
public void setResourceId(String resourceId); // Define o valor criptografado para decodificação

public static String encrypt(String idsConcatenados); // Criptografa uma string de IDs
public static String decrypt(String encodedIds); // Descriptografa uma string de IDs
```

---

## Segurança

- Nunca compartilhe sua chave de criptografia.
- Use uma chave forte e mantenha-a protegida.
- Recomenda-se utilizar variáveis de ambiente para armazenar a chave.

---

## Dicas

- Para suportar tipos personalizados, adicione o tratamento no método `parseId`.
- Para usar em herança, garanta que o método `getIdFields` percorra as superclasses corretamente.
- Sempre trate exceções de criptografia e conversão de tipos.

---
