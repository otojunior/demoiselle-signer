/**
 * 
 */
package org.demoiselle.signer.core.ca.manager.reversetree;

import java.security.cert.X509Certificate;

/**
 * Cache de certificados X509, implementado usando uma árvore reversa para armazenar
 * os certificados e suas relações de hierarquia.
 * @author Oto Soares Coelho Junior (otojunior@gmail.com)
 * @since 28/08/2026
 */
public class X509CertificateCache {
    private ReverseTreeCache<String, X509Certificate> cache = new ReverseTreeCache<>();

    /**
     * Adiciona um certificado X509 ao cache, associando-o ao seu DN e número de série.
     * Se o certificado já estiver presente no cache, o nó existente será retornado.
     * @param value O certificado X509 a ser adicionado.
     * @param parent O certificado pai (pode ser <code>null</code> se não houver pai).
     * @return O nó associado ao certificado fornecido.
     */
    public ReverseTreeNode<X509Certificate> add(
            final X509Certificate value,
            final X509Certificate parent) {
        return cache.add(
            uniquekey(value),
            value,
            parent != null ? uniquekey(parent) : null);
    }

    /**
     * Recupera o nó associado ao certificado X509 fornecido.
     * @param value O certificado X509 a ser recuperado.
     * @return O nó associado ao certificado, ou <code>null</code> se não houver nenhum nó associado.
     */
    public ReverseTreeNode<X509Certificate> get(final X509Certificate value) {
        return cache.get(uniquekey(value));
    }

    /**
     * Verifica se o cache contém um nó associado ao certificado X509 fornecido.
     * @param value O certificado X509 a ser verificado.
     * @return <code>true</code> se o cache contiver um nó associado ao certificado,
     * <code>false</code> caso contrário.
     */
    public boolean contains(X509Certificate value) {
        return cache.contains(uniquekey(value));
    }

    /**
     * Retorna o número de certificados X509 armazenados no cache.
     * @return O tamanho do cache, ou seja, o número de certificados armazenados.
     */
    public int size() {
        return cache.size();
    }

    /**
     * Limpa o cache, removendo todos os certificados X509 armazenados.
     */
    public void clear() {
        cache.clear();
    }
    
    /**
     * Calcula uma chave única para o certificado X509,
     * combinando seu DN e número de série.
     * @param value O certificado X509 a ser computado.
     * @return A chave única composta pelo DN e número de série do certificado.
     */
    public static String uniquekey(final X509Certificate certificate) {
        return
            certificate.getSubjectDN().getName() + 
            certificate.getSerialNumber().toString();
    }
}