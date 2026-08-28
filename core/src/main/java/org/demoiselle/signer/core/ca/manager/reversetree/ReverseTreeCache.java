/**
 * 
 */
package org.demoiselle.signer.core.ca.manager.reversetree;

import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

public final class ReverseTreeCache<K, T> {
    private final ConcurrentHashMap<K, ReverseTreeNode<T>> cache = new ConcurrentHashMap<>();

    /**
     * Adiciona um nó ao cache, associando-o à chave fornecida.
     * Se a chave já estiver presente no cache, o nó existente será retornado.
     * @param key A chave do nó a ser adicionado.
     * @param value O valor do nó a ser adicionado.
     * @param parentKey A chave do nó pai (pode ser <code>null</code> se não houver pai).
     * @return O nó associado à chave fornecida.
     */
    public ReverseTreeNode<T> add(K key, T value, K parentKey) {
        Objects.requireNonNull(key);
        Objects.requireNonNull(value);
        return cache.computeIfAbsent(key, unused -> {
            return new ReverseTreeNode<T>(value, parentKey != null
                ? cache.get(parentKey)
                : null);
        });
    }

    /**
     * Recupera o nó associado à chave fornecida.
     * @param key A chave do nó a ser recuperado.
     * @return O nó associado à chave, ou <code>null</code> se não houver nenhum nó associado.
     */
    public ReverseTreeNode<T> get(K key) {
        return cache.get(key);
    }

    /**
     * Verifica se o cache contém um nó associado à chave fornecida.
     * @param key A chave do nó a ser verificado.
     * @return <code>true</code> se o cache contiver um nó associado
     * à chave, <code>false</code> caso contrário.
     */
    public boolean contains(K key) {
        return cache.containsKey(key);
    }

    /**
     * Retorna o número de nós armazenados no cache.
     * @return O tamanho do cache, ou seja, o número de nós armazenados.
     */
    public int size() {
        return cache.size();
    }

    /**
     * Limpa o cache, removendo todos os nós armazenados.
     */
    public void clear() {
        cache.clear();
    }
}