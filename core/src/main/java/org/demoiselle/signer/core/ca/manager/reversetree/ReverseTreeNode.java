/**
 * 
 */
package org.demoiselle.signer.core.ca.manager.reversetree;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * 
 * @author Oto Soares Coelho Junior (otojunior@gmail.com)
 * @since 26/08/2026
 * Representa um nó em uma árvore reversa, onde cada nó possui
 * um valor e uma referência para o nó pai.
 * @param <T> O tipo do valor armazenado no nó.
 */
public class ReverseTreeNode<T> {
    private T value;
    private ReverseTreeNode<T> parent;

    /**
     * Construtor da classe ReverseTreeNode.
     * @param value O valor do nó.
     * @param parent O nó pai (pode ser <code>null</code> se não houver pai).
     */
    public ReverseTreeNode(
            final T value,
            final ReverseTreeNode<T> parent) {
        this.value = value;
        this.parent = parent;
    }

    /**
     * Verifica se o nó é a raiz da árvore (ou seja, não possui pai).
     * @return <code>true</code> se o nó for a raiz, <code>false</code> caso contrário.
     */
    public boolean isRoot() {
        return parent == null;
    }

    /**
     * Calcula a profundidade do nó na árvore, ou seja,
     * o número de níveis entre o nó atual e a raiz da árvore.
     * @return A profundidade do nó na árvore.
     */
    public int depth() {
        int depth = 0;
        for (ReverseTreeNode<T> current = this;
                current != null;
                current = current.parent) {
            depth++;
        }
        return depth;
    }

    /**
     * Retorna uma lista contendo os valores dos nós desde o nó atual até a raiz da árvore.
     * A lista é construída em ordem do nó atual para a raiz.
     * @return Uma lista imutável contendo os valores dos nós desde o nó atual até a raiz.
     */
    public List<T> pathToRoot() {
        List<T> result = new ArrayList<T>();
        for (ReverseTreeNode<T> current = this;
                current != null;
                current = current.parent) {
            result.add(current.value);
        }
        return Collections.unmodifiableList(result);
    }
}
