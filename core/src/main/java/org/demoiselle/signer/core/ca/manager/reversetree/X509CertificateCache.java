/**
 * 
 */
package org.demoiselle.signer.core.ca.manager.reversetree;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.ListIterator;

/**
 * Cache de certificados X509, implementado usando uma árvore reversa para armazenar os certificados
 * e suas relações de hierarquia.
 * @author Oto Soares Coelho Junior (otojunior@gmail.com)
 * @since 28/08/2026
 */
public class X509CertificateCache {
    private ReverseTreeCache<String, X509Certificate> cache = new ReverseTreeCache<>();

    /**
     * Adiciona um certificado X509 ao cache, associando-o ao seu DN e número de série. Se o certificado
     * já estiver presente no cache, o nó existente será retornado.
     * @param value O certificado X509 a ser adicionado.
     * @param parent O certificado pai (pode ser <code>null</code> se não houver pai).
     * @return O nó associado ao certificado fornecido.
     */
    public ReverseTreeNode<X509Certificate> add(List<X509Certificate> path) {
        ListIterator<X509Certificate> it = path.listIterator(path.size());
        ReverseTreeNode<X509Certificate> issuer = null;
        while (it.hasPrevious()) {
            X509Certificate certif = it.previous();
            issuer = cache.add(uniquekey(certif), certif, issuer);
            issuer.markComplete();
        }
        return issuer;
    }

    /**
     * Recupera o nó associado ao certificado X509 fornecido.
     * @param value O certificado X509 a ser recuperado.
     * @return O nó associado ao certificado, ou <code>null</code> se não houver nenhum nó associado.
     */
    public ReverseTreeNode<X509Certificate> get(final X509Certificate value) {
        ReverseTreeNode<X509Certificate> node = cache.get(uniquekey(value));
        return node != null && node.isComplete()
            ? node
            : null;
    }

    /**
     * Retorna a relação conhecida entre um certificado e seu possível emissor.
     * @param ca O possível certificado emissor.
     * @param certificate O certificado emitido.
     * @return <code>true</code> ou <code>false</code> para uma relação conhecida,
     * ou <code>null</code> se ela ainda não foi avaliada.
     */
    public Boolean getIsCAofCertificate(
            final X509Certificate ca,
            final X509Certificate certificate) {
        ReverseTreeNode<X509Certificate> issuer = cache.get(uniquekey(ca));
        ReverseTreeNode<X509Certificate> certif = cache.get(uniquekey(certificate));
        return issuer != null && certif != null
            ? certif.isIssuedBy(issuer)
            : null;
    }

    /**
     * Registra uma relação válida entre um certificado e seu emissor.
     * Relações inválidas não são armazenadas para evitar crescimento proporcional
     * ao número de pares de certificados testados.
     * @param ca O possível certificado emissor.
     * @param certificate O certificado emitido.
     * @param value Resultado da validação.
     */
    public void setIsCAofCertificate(
            final X509Certificate ca,
            final X509Certificate certificate,
            final boolean value) {
        if (value) {
            String issuerKey = uniquekey(ca);
            String certifKey = uniquekey(certificate);
            ReverseTreeNode<X509Certificate> issuer = cache.add(issuerKey, ca, null);
            
            if (!issuerKey.equals(certifKey)) {
                cache.add(certifKey, certificate, issuer);
            } else {
                issuer.markComplete();
            }
        }
    }

    /**
     * Verifica se o cache contém um nó associado ao certificado X509 fornecido.
     * @param value O certificado X509 a ser verificado.
     * @return <code>true</code> se o cache contiver um nó associado ao certificado, <code>false</code>
     *         caso contrário.
     */
    public boolean contains(X509Certificate value) {
        return get(value) != null;
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
     * Calcula uma chave única para o certificado X509, combinando seu DN e número de série.
     * @param value O certificado X509 a ser computado.
     * @return A chave única composta pelo DN e número de série do certificado.
     */
    public static String uniquekey(final X509Certificate certificate) {
        return
            certificate.getSubjectDN().getName() +
            certificate.getSerialNumber().toString();
    }
}
