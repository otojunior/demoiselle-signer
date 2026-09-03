/**
 * 
 */
package org.demoiselle.signer.core.ca.manager.reversetree;

import java.util.LinkedList;
import java.util.List;

/**
 * 
 * @author Oto Soares Coelho Junior (otojunior@gmail.com)
 * @since 02/07/2026
 * Representa um nó em uma árvore reversa, onde cada nó possui
 * um valor e uma referência para o nó pai.
 * @param <T> O tipo do valor armazenado no nó.
 */
public class ReverseTreeNode<T> {
    private final T value;
    private volatile ReverseTreeNode<T> parent;
    private volatile boolean complete;
    
    /**
     * Construtor da classe ReverseTreeNode.
     */
    public ReverseTreeNode(final T value, final ReverseTreeNode<T> parent) {
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
     * Retorna uma lista contendo os valores dos nós desde o nó atual até a raiz da árvore.
     * A lista é construída em ordem do nó atual para a raiz.
     * @return Uma lista imutável contendo os valores dos nós desde o nó atual até a raiz.
     */
    public List<T> pathToRoot() {
        List<T> result = new LinkedList<>();
        for (ReverseTreeNode<T> current = this;
                current != null;
                current = current.parent) {
            result.add(current.value);
        }
        return result;
    }

    /**
     * Retorna o valor armazenado no nó.
     * @return O valor do nó.
     */
    public T getValue() {
        return value;
    }

    /**
     * Retorna o nó pai do nó atual.
     * @return O nó pai, ou <code>null</code> se o nó atual for a raiz.
     */
    public ReverseTreeNode<T> getParent() {
        return parent;
    }

    /**
     * Retorna a relação conhecida entre este nó e um possível emissor.
     * @param issuer O nó do possível emissor.
     * @return <code>true</code> se for o emissor, <code>false</code> se outro
     * emissor for conhecido e <code>null</code> se a relação ainda for desconhecida.
     */
    public Boolean isIssuedBy(final ReverseTreeNode<T> issuer) {
        ReverseTreeNode<T> currentParent = parent;
        if (currentParent != null) {
            return currentParent == issuer;
        }
        return complete
            ? issuer == this
            : null;
    }

    /**
     * Define o emissor deste nó caso ele ainda não seja conhecido.
     * @param issuer O nó emissor.
     */
    public synchronized void setParent(final ReverseTreeNode<T> issuer) {
        if (parent == null && issuer != this && !complete) {
            parent = issuer;
        }
    }

    /**
     * Marca que o caminho deste nó até a raiz está completo.
     */
    public void markComplete() {
        complete = true;
    }

    /**
     * Indica se o caminho deste nó até a raiz está completo.
     * @return <code>true</code> se o caminho estiver completo.
     */
    public boolean isComplete() {
        return complete;
    }
}
