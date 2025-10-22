package idhash;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

public class EnderecoModelIdPresenterTest {

    @Test
    void testEncodeDecodeAndEquals() {
        Long id = 12345L;
        EnderecoModelIdPresenter vm = new EnderecoModelIdPresenter(id);
        String token = vm.getResourceId();
        assertNotNull(token);

        EnderecoModelIdPresenter parsed = EnderecoModelIdPresenter.valueOf(token);
        assertNotNull(parsed);
        assertEquals(id, parsed.getIdEndereco());

        // equals/hashCode via Lombok annotation
        EnderecoModelIdPresenter vm2 = new EnderecoModelIdPresenter(id);
        assertTrue(vm.equals(vm2));
    }
}
