import socket
import time
import re
import urlparse
import sys
import os
from threading import *
import ssl

import pprint

# FLAGS PARA DEBUG

# SEM ESCRITA
# Quando ela eh True, nenhum arquivo ou diretorio eh criado.
# Adicionalmente, mensagens de erro mais completas sao mostradas.
DEBUG_FLAG = True

# IMPRIME CABECALHO
# Quando ela eh True, o cabecalho obtido como resposta eh mostrado abaixo do
# endereco do site
IMPRIME_CABECALHO = False

NTHREADS = 1
BLOCO = 2048

def SinalizaErro():
# Apenas por economia
	if DEBUG_FLAG:		# DEBUG
		erro = sys.exc_info()[:2]
		ret = str(erro)

	else:
		ret = '\t<erro>\n'

	return ret


def GeraLink(scheme, host, path, s):
	ret = s

	if (re.match(r'mailto:|javascript:|JavaScript:', s)):
		ret = ""

	else:
		if re.match(r'//', s):
			ret = scheme + ":" + s
		elif re.match(r'/', s):
			ret = scheme + "://" + host + s

		elif not(re.match(r'https?://', s)):
			ret = scheme + "://" + path + '/' + s

	return ret


def CriaDiretorios(host, path, criar):
	# Diretorio correspondente ao host
	caminho = host
	lock.acquire()

	if not (caminho in diretorios):
		if criar:
			diretorios.append(caminho)
		lock.release()

		if criar and (not DEBUG_FLAG):		# DEBUG
			os.system("mkdir webcrawler-output/" + caminho + ' 2>> /dev/null')

	else:
		lock.release()

	# Diretorios correspondentes ao path
	novalista = re.split(r'/', path)
	novalista.pop()			# o ultimo elemento eh um nome de arquivo e nao de pasta

	if novalista:
		novalista.pop(0)	# o primeiro elemento eh uma string nula

	npastas = len(novalista)

	i = 0
	while i < npastas:
		caminho = caminho + '/' + novalista[i]
		lock.acquire()

		if not (caminho in diretorios):
			if criar:
				diretorios.append(caminho)
			lock.release()

			if criar and (not DEBUG_FLAG):		# DEBUG
				os.system("mkdir webcrawler-output/" + caminho + ' 2>> /dev/null')

		else:
			lock.release()

		i = i + 1

	return caminho



def Busca(url, prof_atual):

	#print "Passei [-1]"

	global lista_por_visitar

	houve_erro = False

	parse = urlparse.urlparse(url)
	host = parse.netloc
	path = parse.path
	
	try:
		if parse.port == None:
			port = 80
		else:
			port = parse.port

	except:
		port = 80
	
	addr = host + path

	lock.acquire()
	if not (addr in lista_visitados):

		#print "Passei [0]"

		lista_visitados.append(addr)
		lock.release()

		scheme = parse.scheme

		if scheme == "https":
			https = True
		else:
			https = False

		msg = scheme + '://' + host + path + ', ' + str(prof_atual) + '\n'

		if not path:
			path = '/'

		#print "Passei [1]"

		if https:
			s = socket.socket()
			#try:
			#	cert = ssl.get_server_certificate((host, 443))
			#	certfile = open("temp.pem", 'w')
			#	certfile.write(cert)
			#	certfile.close()
			#	os.system ('openssl verify -CAfile temp.pem temp.pem')
			#except:
			#	print "Nao foi possivel obter o certificado do servidor."
			ss = ssl.wrap_socket(s, ca_certs="ca-certificates.crt", cert_reqs=ssl.CERT_NONE)
			ss.connect((host, 443))
			#cert = ssl.get_server_certificate((host,443))
			cert = ss.getpeercert(True)
			cert = ssl.DER_cert_to_PEM_cert(cert)
			if cert:
				lock.acquire()
				certfile = open("temp.pem", 'w')
				certfile.write(cert)
				certfile.close()
				os.system("openssl x509 -in temp.pem -text -noout > temp2.pem")
				#os.system ('openssl verify -CAfile temp2.pem temp2.pem')
				certfile_decodificada = open("temp2.pem", 'r')
				cert = certfile_decodificada.read()
				certfile_decodificada.close()
				os.system ('rm temp.pem temp2.pem')
				lock.release()
				match1 = re.search(r"\s*?Issuer:.*?O=(.*?),", cert, re.DOTALL)
				if match1:
					issuer = match1.group(1)
					msg += "\tEmitido por: " + issuer + "\n"
				match2 = re.search(r"\s*?Subject:.*?O=(.*?),", cert, re.DOTALL)
				if match2:
					subject = match2.group(1)
					msg += "\tEmitido para: " + subject + "\n"
				if match1 and match2 and (issuer == subject):
					msg += "\t(o certificado eh auto-assinado)" + "\n"

			ss.write("GET " + path + " HTTP/1.1\r\nHost: "+ host + "\r\n\r\n")
			strg = ss.recv(BLOCO)
		else:
			# Inicia a comunicacao, envia a requisicao e recebe o cabecalho
			# mais o inicio do conteudo, se houver
			try:

				s = socket.create_connection((host, port), 10)
				s.send("GET " + path + " HTTP/1.1\r\nHost: "+ host + "\r\n\r\n")
				strg = s.recv(BLOCO)
			
			except socket.error:
				msg += SinalizaErro()
				houve_erro = True

		#print "Passei [2]"

		if not houve_erro:

			bytes_recebidos = len(strg)

			# Separa o cabecalho do inicio do conteudo
			resposta = re.match(r'(.*?)\n\r\n(.*)', strg, re.DOTALL)
			if resposta:
				cabecalho = resposta.group(1)
				conteudo = resposta.group(2)

				if IMPRIME_CABECALHO:
					print '\n' + cabecalho + '\n\n'
			
				# Define se a requisicao foi bem sucedida
				codigo_retorno = int(cabecalho.split(" ", 2)[1])

				match = re.search(r'Transfer-Encoding: chunked', cabecalho)
				
				if match:
					chunked_encoding = True
				else:
					chunked_encoding = False

					# Verifica se o cabecalho disponibiliza o tamanho do
					# conteudo
					match = re.search(r'Content-Length: (\d+)', cabecalho)

					if match:
						tamanho_disponivel = True
						tam = int(match.group(1))

					else:
						tamanho_disponivel = False
			
			
				if codigo_retorno == 200 or codigo_retorno == 300:
				# Site encontrado

					# Assegura que os diretorios necessarios
					# existem
					caminho = CriaDiretorios(host,path,True)
				
					# Monta o caminho do arquivo de saida
					re_arquivo = re.search(r'/([^/]+)$', path)

					if re_arquivo:
						arq = re_arquivo.group(1)

					else:
						arq = 'index.html'
				
					nome = 'webcrawler-output/' + caminho + '/' + arq

				
					if not DEBUG_FLAG:		# DEBUG
						saida = open(nome, 'w')
				
					if not DEBUG_FLAG:		# DEBUG
						saida.write(conteudo)

					# Recebe o restante do conteudo
					# Se houver indicacao explicita de content-length,
					# ela deve ser respeitada. Senao, paramos quando o
					# server para de mandar.
											
					if chunked_encoding:
						#print "Site usa chunked encoding"
						#print "Entrei [1]"
						#print conteudo
						temp = re.split(r'\r\n', conteudo, 1)
						while (not temp[0]):
							try:
								if https:
									conteudo += ss.recv(BLOCO)
								else:
									conteudo += s.recv(BLOCO)
							except:
								msg += SinalizaErro()
								houve_erro = True
								break
							temp = re.split(r'\r\n', conteudo, 1)
						bytes_para_ler = int(temp[0],16)
						while bytes_para_ler > 0:
							renomear_isso = temp[1]
							while bytes_para_ler + 2 > len(renomear_isso):
								try:
									if https:
										strg = ss.recv(BLOCO)
									else:
										strg = s.recv(BLOCO)
									renomear_isso += strg
								except:
									msg += SinalizaErro()
									houve_erro = True
									break
							#temp = re.split ('.{bytes_para_ler+2}', renomear_isso, re.DOTALL)
							strg = renomear_isso[0:(bytes_para_ler+2)]
							if (len(strg) < len(renomear_isso)):
								resto = renomear_isso[(bytes_para_ler+2):(len(renomear_isso))]
							else:
								resto = ""
							#strg = temp[0]
							conteudo += strg
							
							#print strg
							
							if not DEBUG_FLAG:		# DEBUG
								saida.write(strg)
							if (not resto):
								try:
									if https:
										strg = ss.recv(BLOCO)
									else:
										strg = s.recv(BLOCO)
									resto += strg
								except:
									msg += SinalizaErro()
									houve_erro = True
									break
								temp = re.split(r'\r\n', resto, 1)
								bytes_para_ler = int(temp[0],16)
							else:
								#strg = temp[1]
								temp = re.split(r'\r\n', resto, 1)
								bytes_para_ler = int(temp[0],16)
						
							
					elif tamanho_disponivel:
						#print "Site usa content-length"
						bytes_recebidos = len(conteudo)

						while (bytes_recebidos < tam):

							try:
								if https:
									strg = ss.recv(BLOCO)
								else:
									strg = s.recv(BLOCO)
								# print len(strg)
								ultimo_br = bytes_recebidos
								bytes_recebidos += len(strg)
								conteudo = conteudo + strg

								if not DEBUG_FLAG:		# DEBUG
									saida.write(strg)

								if bytes_recebidos == ultimo_br:
									break

							except:
								msg += SinalizaErro()
								houve_erro = True
								break

					else:
						#print "Site nao usa nada"
						tentativas = 5

						while(tentativas > 0):

							try:
								if https:
									strg = ss.recv(BLOCO)
								else:
									strg = s.recv(BLOCO)
								bytes_recebidos = (len(strg))
								conteudo = conteudo + strg

								if not DEBUG_FLAG:		# DEBUG
									saida.write(strg)

							except:
								msg += SinalizaErro()
								houve_erro = True
								break

							if bytes_recebidos == 0:
								tentativas -= 1

							else:
								tentativas = 5

					# print conteudo
					#print "Sai [1]"

					if not DEBUG_FLAG:		# DEBUG
						saida.close()

					# Procura todos os links dentro de tags
					# <a href> na pagina recebida
					strg = conteudo
					strg = re.sub(r'<!--[\w\W]*?-->',r'',strg)
					matchies = re.findall(r'<a [\w\W]*?href=\"([^\"]+)\"',strg)

					visitar = []

					for match in matchies:
						link = GeraLink(parse.scheme, host, caminho, match)
						if link:
							visitar.append(link)

					lock.acquire()
					lista_por_visitar += visitar
					lock.release()
				
					if not houve_erro:
						msg += "\t<recebido>\n"
				
					print msg
			
				elif codigo_retorno == 301 or codigo_retorno == 302 or codigo_retorno == 307:
				# Fui redirecionado!

					caminho = CriaDiretorios(host,path,False)
				
					re_novo_endereco = re.search(r'Location: (.+)\r', cabecalho)

					if re_novo_endereco:
						novo_endereco = re_novo_endereco.group(1)

						novo_endereco = GeraLink(parse.scheme, host, caminho, novo_endereco)

						msg += '\t<redirecionado para ' + str(novo_endereco) + '>\n'
						print msg

						Busca(novo_endereco, prof_atual)

					else:
						msg += '\t<redirecionado sem endereco destino>\n'
						print msg
			
				else:
					msg += '\t<resposta com codigo invalido>\n'
					print msg
						
				if https:
					ss.close()
				else:
					s.close()
	else:
		lock.release()

def robots(url):
	resposta = ''
	msg = ''

	houve_erro = False

	parse = urlparse.urlparse(url)

	if not (parse.netloc in robots_visitados):
		robots_visitados.append(parse.netloc)
		scheme = parse.scheme

		try:
			if parse.port == None:
				port = 80
			else:
				port = parse.port

		except:
			port = 80

		if scheme == "https":
			https = True
		else:
			https = False

		msg = parse.netloc + '/robots.txt' + '\n'

		if https:
			s = socket.socket()
			ss = ssl.wrap_socket(s, ca_certs="ca-certificates.crt", cert_reqs=ssl.CERT_NONE)
			ss.connect((parse.netloc, 443))
			ss.write("GET /" + "/robots.txt" + " HTTP/1.1\r\nHost: "+ parse.netloc + "\r\n\r\n")
			result = ss.recv(BLOCO)
		else:

			try:
				s = socket.create_connection((parse.netloc, port), 10)
				s.send("GET /" + "/robots.txt" + " HTTP/1.1\r\nHost: "+ parse.netloc + "\r\n\r\n")
				if https:
					result = ss.recv(BLOCO)
				else:
					result = s.recv(BLOCO)

			except socket.error:
				SinalizaErro()
				houve_erro = True
			except ssl.SSLError:
				SinalizaErro()
				houve_erro = True

		if houve_erro:
			return

		resposta = re.match(r'(.*?)\n\r\n(.*)', result, re.DOTALL)
		cabecalho = resposta.group(1)
		conteudo = resposta.group(2)
		
		match = re.search(r'Transfer-Encoding: chunked', cabecalho)
		if match:
			chunked_encoding = True
		else:
			chunked_encoding = False

		codigo_retorno = int(cabecalho.split(' ', 2)[1])

		if codigo_retorno != 200:
			return

		re_tamanho = re.search(r'Content-Length: (.*)', cabecalho)
		if re_tamanho:
			tam = int(re_tamanho.group(1))

		if chunked_encoding:
			temp = re.split(r'\r\n', conteudo, 1)
			bytes_para_ler = int(temp[0],16)
			#print "Bytes para ler " + str(bytes_para_ler)
			while bytes_para_ler > 0:
				renomear_isso = temp[1]
				#print "REnomear isso " + renomear_isso
				while bytes_para_ler + 2 > len(renomear_isso):
					try:
						if https:
							strg = ss.recv(BLOCO)
						else:
							strg = s.recv(BLOCO)
						renomear_isso += strg
					except:
						msg += SinalizaErro()
						houve_erro = True
						break
				#print "Passei o primeiro while"
				strg = renomear_isso[0:(bytes_para_ler+2)]
				if (len(strg) < len(renomear_isso)):
					resto = renomear_isso[(bytes_para_ler+2):(len(renomear_isso))]
				else:
					resto = ""
				
				#print len(strg)
				#print strg
				conteudo += strg
				if (not resto):
					try:
						if https:
							strg = ss.recv(BLOCO)
						else:
							strg = s.recv(BLOCO)
						resto += strg
					except:
						msg += SinalizaErro()
						houve_erro = True
						break
					temp = re.split(r'\r\n', resto, 1)
					bytes_para_ler = int(temp[0],16)
					#print "Sai do IF"
				else:
					#print "Entrei no ELSE"
					strg = resto
					temp = re.split(r'\r\n', strg, 1)
					bytes_para_ler = int(temp[0],16)
					#print "Sai do ELSE"
			#print "Voltei da iteracao"
		elif re_tamanho:
			while len(conteudo) < tam:
				try:
					if https:
						result = ss.recv(BLOCO)
					else:
						result = s.recv(BLOCO)
					conteudo += result
				except:
					SinalizaErro()
					houve_erro = True
					break
		else:
			tentativas = 5
			while(tentativas > 0):
				try:
					if https:
						result = ss.recv(BLOCO)
					else:
						result = s.recv(BLOCO)
					conteudo += result
					bytes_recebidos = len(result)
				except:
					SinalizaErro()
					houve_erro = True
					break
				if bytes_recebidos == 0:
					tentativas -= 1
				else:
					tentativas = 5

		if houve_erro:
			return

		matchies = re.findall(r'[Dd]isallow: (.*)', conteudo)
		for match in matchies:
			link = parse.netloc + match
			if not (link in lista_visitados):
				lista_visitados.append(link)
				msg += 'robots.txt: ' + link + '\n'

		print msg
		
		#print "Saindo do robots"

def procura():

	global nsites
	global prof_atual

	#print "Procura em [1]"

	while True:

		lock.acquire()

		#print "Procura em [2]"

		nsites_local = nsites
		if nsites_local > 0:
			url = lista_por_visitar.pop(0)
			#print "URL " + url
			parse = urlparse.urlparse(url)
			#print "Parse.netloc " + parse.netloc
			if not (parse.netloc in robots_visitados):
				robots(url)
			nsites -= 1

		#print "Procura em [3]"

		lock.release()
		
		#print "Procura em [4]"

		if nsites_local > 0:
			Busca(url, prof_atual)
		else:
			break

	#print "Procura em [5]"


def main(argc, argv):

	global nsites
	global prof_atual

	#print "Main em [1]"

	if argc != 3:
		print "Numero de parametros incorreto"
		print "Uso: python webcrawler.py <profundidade> <url>\n"
		sys.exit()

	#print "Main em [2]"

	try:
		profundidade = int(argv[1])
	except ValueError:
		print "Profundidade deve ser um inteiro!"
		print "Uso: python webcrawler.py <profundidade> <url>\n"
		sys.exit()

	#print "Main em [3]"

	URL_inicial = argv[2]
	
	#print "Main em [4]"

	#Cria o diretorio que vai conter todos as outras pastas dos hrefs
	os.system("mkdir webcrawler-output" + ' 2>> /dev/null')


	if not(re.match(r'https?://', URL_inicial)):
		URL_inicial = "http://" + URL_inicial

	#print "Main em [5]"

	lista_por_visitar.append(URL_inicial)

	#print "Main em [6]"

	while prof_atual <= profundidade:								# Profundidade
		threads = []
		nsites = len(lista_por_visitar)

		#print "Main em [7]"


		if nsites < NTHREADS:
			nthreads = nsites
		else:
			nthreads = NTHREADS

		k = 0
		while k < nthreads:
			t = Thread (target=procura)
			threads.append(t)
			t.start()
			k += 1
			
		#print "Main em [8]"

		k = 0
		while k < nthreads:
			t = threads.pop()
			t.join()
			k += 1
			
		#print "Main em [9]"

		prof_atual += 1


robots_visitados = []
lista_visitados = []
diretorios = []
lista_por_visitar = []
lock = Lock()
nsites = 0
prof_atual = 0

if __name__ == '__main__': main(len(sys.argv), sys.argv)
