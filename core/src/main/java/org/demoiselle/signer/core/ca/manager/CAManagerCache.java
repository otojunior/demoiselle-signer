/*
 * Demoiselle Framework
 * Copyright (C) 2016 SERPRO
 * ----------------------------------------------------------------------------
 * This file is part of Demoiselle Framework.
 *
 * Demoiselle Framework is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License version 3
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License version 3
 * along with this program; if not,  see <http://www.gnu.org/licenses/>
 * or write to the Free Software Foundation, Inc., 51 Franklin Street,
 * Fifth Floor, Boston, MA  02110-1301, USA.
 * ----------------------------------------------------------------------------
 * Este arquivo é parte do Framework Demoiselle.
 *
 * O Framework Demoiselle é um software livre; você pode redistribuí-lo e/ou
 * modificá-lo dentro dos termos da GNU LGPL versão 3 como publicada pela Fundação
 * do Software Livre (FSF).
 *
 * Este programa é distribuído na esperança que possa ser útil, mas SEM NENHUMA
 * GARANTIA; sem uma garantia implícita de ADEQUAÇÃO a qualquer MERCADO ou
 * APLICAÇÃO EM PARTICULAR. Veja a Licença Pública Geral GNU/LGPL em português
 * para maiores detalhes.
 *
 * Você deve ter recebido uma cópia da GNU LGPL versão 3, sob o título
 * "LICENCA.txt", junto com esse programa. Se não, acesse <http://www.gnu.org/licenses/>
 * ou escreva para a Fundação do Software Livre (FSF) Inc.,
 * 51 Franklin St, Fifth Floor, Boston, MA 02111-1301, USA.001011
 */

package org.demoiselle.signer.core.ca.manager;

import static org.demoiselle.signer.core.ca.manager.reversetree.X509CertificateCache.uniquekey;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import org.demoiselle.signer.core.ca.manager.reversetree.ReverseTreeNode;
import org.demoiselle.signer.core.ca.manager.reversetree.X509CertificateCache;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Classe responsável por gerenciar o cache de certificados X.509.
 * Implementa o padrão Singleton para garantir que apenas uma instância
 * do cache seja criada durante a execução da aplicação.
 * @author Oto Soares Coelho Junior (otojunior@gmail.com)
 * @since 28/08/2026
 */
public class CAManagerCache {
    private static final Logger LOGGER = LoggerFactory.getLogger(CAManagerCache.class);
	private static CAManagerCache instance;
	private X509CertificateCache cache = new X509CertificateCache();
	private Map<String, Boolean> cacheCaCert = new HashMap<>();

	/**
	 * Constructor privado para evitar a criação de instâncias externas.
     */
	private CAManagerCache() { }

	/**
     * Retorna a instância única do CAManagerCache.
     * Se a instância ainda não foi criada, ela será inicializada.
     * @return A instância única do CAManagerCache.
     */
	public static CAManagerCache getInstance() {
		if (instance == null) {
			instance = new CAManagerCache();
		}
		return instance;
	}

    /**
     * Retorna a coleção de certificados em cache para o certificado fornecido.
     * @param certificate O certificado X.509 para o qual os
     * certificados em cache serão recuperados.
     * @return A coleção de certificados em cache associados ao certificado fornecido.
     */
	Collection<X509Certificate> getCachedCertificatesFor(final X509Certificate certificate) {
        ReverseTreeNode<X509Certificate> node = cache.get(certificate);
        logTraceGet(certificate, node);
        return node != null
            ? node.pathToRoot()
            : null;
    }

	/**
     * Adiciona um certificado e sua cadeia de certificados em cache.
     * @param certificate O certificado X.509 a ser adicionado ao cache.
     * @param certificates A coleção de certificadosque representam a cadeia de certificados.
     */
	synchronized void addCertificate(
	        final X509Certificate certificate,
	        final Collection<X509Certificate> certificates) {
	    Iterator<X509Certificate> it = certificates.iterator();
	    if (it.hasNext()) {
	        X509Certificate atual = it.next();
	        while (it.hasNext()) {
	            X509Certificate proximo = it.next();
	            cache.add(atual, proximo);
	            logTraceAdd(atual, proximo);
	            atual = proximo;
	        }
	    }
	}

	/**
     * Verifica se um certificado é uma Autoridade Certificadora (CA) para outro certificado.
     * @param ca O certificado que será verificado como CA.
     * @param certificate O certificado para o qual a relação de CA será verificada.
     * @return <code>true</code> se o certificado for uma CA para o outro certificado,
     * <code>false</code> caso contrário, ou <code>null</code> se a relação não estiver em cache.
     */
    Boolean getIsCAofCertificate(
            final X509Certificate ca,
            final X509Certificate certificate) {
        String key = uniquekey(ca) + "|" + uniquekey(certificate);
        logTraceGetIsCAofCert(ca, certificate, key);
        return cacheCaCert.containsKey(key)
            ? cacheCaCert.get(key)
            : null;
    }

	/**
     * Define se um certificado é uma Autoridade Certificadora (CA) para outro certificado.
     * @param ca O certificado que será definido como CA.
     * @param certificate O certificado para o qual a relação de CA será estabelecida.
     * @param value Valor booleano indicando se o certificado é uma CA (true) ou não (false).
     */
	synchronized void setIsCAofCertificate(
	        final X509Certificate ca,
	        final X509Certificate certificate,
	        boolean value) {
	    String key = uniquekey(ca) + "|" + uniquekey(certificate);
		cacheCaCert.put(key, value);
		logTraceSetIsCAofCertificate(ca, certificate, value);
	}

	/**
     * Invalida o cache, removendo todos os certificados armazenados.
     */
	public synchronized void invalidate() {
        cache.clear();
        cacheCaCert.clear();
	}
	
	/**
     * Método auxiliar para registrar informações de rastreamento (trace)
     * sobre o certificado e seu caminho no cache.
     * @param certificate O certificado X.509 que está sendo verificado no cache.
     * @param node O nó da árvore reversa correspondente ao certificado no cache.
     */
	private void logTraceGet(
            final X509Certificate certificate,
            ReverseTreeNode<X509Certificate> node) {
        if (LOGGER.isTraceEnabled()) {
            if (node != null) {
                LOGGER.trace("(Get) CN={}", cn(certificate));
                node.pathToRoot()
                    .forEach(c -> LOGGER.trace("(Get) Elemento CN={}", cn(c)));
            } else {
                LOGGER.trace("(Get) !VAZIO! CN={}", cn(certificate));
            }
        }
    }

	/**
     * Método auxiliar para registrar informações de rastreamento (trace)
     * sobre a adição de um certificado ao cache.
     * @param atual O certificado X.509 atual que está sendo adicionado ao cache.
     * @param proximo O próximo certificado X.509 na cadeia que está sendo adicionado ao cache.
     */
	private void logTraceAdd(X509Certificate atual, X509Certificate proximo) {
        if (LOGGER.isTraceEnabled()) {
            LOGGER.trace("(Add) CN={} -> CN={}",
                cn(atual),
                cn(proximo));
        }
    }

	/**
     * Método auxiliar para registrar informações de rastreamento (trace)
     * sobre a verificação se um certificado é uma Autoridade Certificadora (CA)
     * para outro certificado.
     * @param ca O certificado X.509 que está sendo verificado como CA.
     * @param certificate O certificado X.509 para o qual a relação de CA está sendo verificada.
     * @param key A chave única que representa a relação entre os dois certificados no cache.
     */
	private void logTraceGetIsCAofCert(
            final X509Certificate ca,
            final X509Certificate certificate,
            String key) {
        if (LOGGER.isTraceEnabled()) {
            LOGGER.trace("(Is-CAofCert) {} | {}? {}",
                cn(ca),
                cn(certificate),
                cacheCaCert.containsKey(key)
                    ? cacheCaCert.get(key)
                    : "!NULL!");
        }
    }

	/**
     * Método auxiliar para registrar informações de rastreamento (trace)
     * sobre a definição de um certificado como Autoridade Certificadora (CA)
     * para outro certificado.
     * @param ca O certificado X.509 que está sendo definido como CA.
     * @param certificate O certificado X.509 para o qual a relação de CA está sendo estabelecida.
     * @param value Valor booleano indicando se o certificado é uma CA (true) ou não (false).
     */
	private void logTraceSetIsCAofCertificate(
            final X509Certificate ca,
            final X509Certificate certificate,
            boolean value) {
        if (LOGGER.isTraceEnabled()) {
            LOGGER.trace("(Set-CAofCert) {} | {}: {}",
                cn(ca),
                cn(certificate),
                value);
        }
    }

	/**
     * Método auxiliar para extrair o Common Name (CN) de um certificado X.509.
     * @param certificate O certificado X.509 do qual o CN será extraído.
     * @return O Common Name (CN) do certificado.
     */
	private String cn(final X509Certificate certificate) {
        return certificate
            .getSubjectX500Principal()
            .getName()
            .replaceFirst(".*CN=([^,]+).*", "$1");
    }
}
