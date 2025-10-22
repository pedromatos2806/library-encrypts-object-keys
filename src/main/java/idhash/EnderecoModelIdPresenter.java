package idhash;

import lombok.EqualsAndHashCode;
import lombok.Getter;

@EqualsAndHashCode(onlyExplicitlyIncluded = true, callSuper = false)
@Getter
public class EnderecoModelIdPresenter extends ObjectObfuscator {

    @ResourceId
    @EqualsAndHashCode.Include
    private Long idEndereco;

    public EnderecoModelIdPresenter(Long idEndereco) {
        this.idEndereco = idEndereco;
        this.encode();
    }

    private EnderecoModelIdPresenter() {
    }

    public static EnderecoModelIdPresenter valueOf(String resourceId) {
        EnderecoModelIdPresenter vm = new EnderecoModelIdPresenter();
        vm.setResourceId(resourceId);
        vm.decode();
        return vm;
    }

}
