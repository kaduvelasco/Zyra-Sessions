# Zyra Sessions

<!-- Project Shields -->
[![OpenSource](https://img.shields.io/badge/OPEN-SOURCE-green?style=for-the-badge)](https://opensource.org/)
[![GitHub license](https://img.shields.io/github/license/kaduvelasco/zyra-sessions?style=for-the-badge)](https://github.com/kaduvelasco/zyra-sessions/blob/main/LICENSE)
[![PHP7.4](https://img.shields.io/badge/PHP-7.4-blue?style=for-the-badge)](https://www.php.net/)
[![PSR-12](https://img.shields.io/badge/PSR-12-orange?style=for-the-badge)](https://www.php-fig.org/psr/psr-12/)

> Uma classe PHP para trabalhar com sessões em PHP.

>- [Começando](#-começando)
>- [Pré-requisitos](#-pré-requisitos)
>- [Instalação](#-instalação)
>- [Utilização](#-utilização)
>- [Colaborando](#-colaborando)
>- [Versão](#-versão)
>- [Autores](#-autores)
>- [Licença](#-licença)

## 🚀 Começando

Esta é uma classe simples para trabalhar com sessões em PHP.

## 📋 Pré-requisitos

- PHP 7.4 ou superior
- Extensão json (ext-json)

## 🔧 Instalação

Utilizando um arquivo `composer.json`:

```json
{
    "require": {
        "kaduvelasco/zyra-sessions": "^1"
    }
}
```

Depois, execute o comando de instalação.

```
$ composer install
```

OU execute o comando abaixo.

```
$ composer require kaduvelasco/zyra-sessions
```

## 💻 Utilização

### Diretório para armazenar os logs

O diretório onde as sessões serão armazenadas deve existir no servidor e possuir a permissão de escrita.

### Utilizando a Zyra Sessions em seu projeto

A utilização da classe é bem simples. Veja um exemplo:

```php
declare(strict_types=1);

namespace Zyra;

require_once 'vendor' . DIRECTORY_SEPARATOR . 'autoload.php';

$ssn = new Sessions();
$ssn->initialize();
```

#### Definindo as configurações

As configurações podem ser feitas de três formas. A primeira é através de um array informado no momento em que a classe é instanciada. O array deve ser como o mostrado abaixo.

```php
# Atenção:
# O tipo da variável e o valor padrão que ela possui na classe estão definidos no exemplo.
# Caso você não queira mudar o valor padrão, basta não definir a chave de configuração.

$config = [
     # Diretório onde as sessões serão salvas.
     # Precisa ser um diretório válido com permissão de escrita.
     # O valor padrão null mantém as configurações padrão definidas no php.ini
    'save_path' => null,
    
    # Define se as sessões serão iniciadas automaticamente.
    'auto_start' => false,
    
    # Em conjunto com o gc_divisor, calcula a porcentagem de chance do GC (coletor de lixo)
    # ser chamado na inicialização da sessão.
    'gc_probability' => 1,
    
    # Em conjunto com o gc_probability, calcula a porcentagem de chance do GC (coletor de lixo)
    # ser chamado na inicialização da sessão.
    'gc_divisor' => 100,
    
    # Tempo, em segundos que os dados são considerados "lixo" e enviados ao GC.
    'gc_maxlifetime' => 1800,
    
    # Define se só será utilizado cookies para guardar o ID no lado do cliente.
    # Previne ataques envolvendo passagem de IDs de sessão nas URLs.
    'use_only_cookies' => true,
    
    # Define se os dados só serão reescritos em caso de mudança.
    'lazy_write' => true,
    
    # Define se os métodos de sessão serão rigorosos (strict).
    'use_strict_mode' => true,
    
    # Tamanho do texto do id de sessão. Deve estar no intervalo de 22 até 256
    'sid_length' => 32,
    
    # Número de bits codificados no ID de sessão. São possíveis:
    # * 4: (0-9,a-f)
    # * 5: (0-9,a-v)
    # * 6: (0-9,a-z,A-Z,'-',',')
    'sid_bits_per_character' => 5,
    
    # Define o tempo de vida, em segundos, do cookie. O valor zero define até o fechamento do navegador.
    'cookie_lifetime' => 0,
    
    # Define o caminho para definir em session_cookie.
    'cookie_path' => '/',
    
    # Define o domínio para definir no cookie de sessão.
    'cookie_domain' => $_SERVER['SERVER_NAME'],
    
    # Define se o cookie será enviado apenas em conexões seguras.
    'cookie_secure' => false,
    
    # Define se o cookie será acessível apenas pelo protocolo HTTP.
    # Reduz o roubo de identidade através de ataques XSS.
    'cookie_httponly' => true,
    
    # Cookie deve ou não ser enviado em solicitações entre sites.
    # Reduz o risco de vazamento de informações de origem cruzada.
    # Valores possíveis: 'Strict', 'Lax'
    'cookie_samesite' => 'Strict',
    
    # Limitador do cache atual.
    # Valores possíveis: 'public', 'private_no_expire', 'private', 'nocache'
    'cache_limiter' => 'public',
    
    # Tempo em que o cache irá expirar.
    'cache_expires' => 180,
    
    # Define o nome da sessão.
    'session_name' => 'ZyraSession',
    
    # Define a chave do array da sessão que será utilizada.
    'session_key' => 'ZS',
    
    # Define o método de hash utilizado na classe.
    # Deve ser um método disponível no servidor.
    'hash_algorithm' => 'sha256',
    
    # Define se um cookie "isca" será criado.
    'generate_decoy' => true,
    
    # Tempo, em segundo que será adicionado sempre que uma sessão for regenerada.
    'regenerate_time' => 600,
    
    # Define o fuso horário.
    'timezone' => 'America/Sao_Paulo',
    
    # Define o status de debug.
    'debug' => false,
];

$ssn = new Sessions($config);
```

A segunda é utilizando o método `setConfig()` passando o array de configurações.

```php
$ssn->setConfig($config);
```

E a terceira é utilizando os métodos específicos de configuração.

```php
$ssn->setSavePath(string $save_path);
$ssn->setAutoStart(bool $auto_start);
$ssn->setGcProbability(int $probability);
$ssn->setGcDivisor(int $divisor);
$ssn->setGcMaxLifetime(int $max_lifetime);
$ssn->setUseOnlyCookies(bool $only_cookies);
$ssn->setLazyWrite(bool $lazy_write);
$ssn->useStrictMode(bool $strict_mode);
$ssn->setSidLength(int $length);
$ssn->setSidBitsPerCharacter(int $bits);
$ssn->setCookieLifetime(int $lifetime);
$ssn->setCookiePath(string $path);
$ssn->setCookieDomain(string $domain);
$ssn->setCookieSecure(bool $secure);
$ssn->setCookieHttpOnly(bool $http_only);
$ssn->setCookieSameSite(string $samesite);
$ssn->setCacheLimiter(string $limiter);
$ssn->setCacheExpires(int $expires);
$ssn->setSessionName(string $session_name);
$ssn->setSessionKey(string $session_key);
$ssn->setHashAlgorithm(string $hash_algorithm);
$ssn->setGenerateDecoy(bool $generate_decoy);
$ssn->setRegenerateTime(int $time);
$ssn->setTimezone(string $timezone);
$ssn->setDebug(bool $debug);
```

#### Iniciando a sessão

Após definir as configurações é preciso iniciar a sessão. Isso é feito utilizando o método `initialize()`.

Caso queira reiniciar a sessão, basta chamar o método `initialize(true)`;

```php
$ssn->initialize();
# Inicia a sessão.

$ssn->initialize(true);
# Reinicia a sessão.
```

#### Trabalhando com a sessão

##### Método set()

Cria (ou atualiza, se já existir) um valor na sessão.

```php
$ssn->set(string $key, $value, bool $hash = false);
# $key: Chave que será criada/atualizada
# $value: Valor que a chave terá
# $hash: false indica que o valor será armazenado como texto simples
#        true indica que o valor será armazenado criptografado com o algorítmo de hash definido
```

##### Método get()

Retorna o valor da chave informada. Caso não exista, retorna null.

```php
$ssn->get(string $key);
```

##### Método append()

Este método permite anexar um valor a uma chave armazenada na sessão.

Seu comportamento depende do tipo do valor armazenado na sessão:
- Se for um array, o valor é adicionado ao array (array_merge).
- Se for uma string, o valor é adicionado no final da string (concatenação).
- Qualquer outro tipo tem o valor substituído.

```php
$ssn->append(string $key, $value);
```

##### Método increment()

Este método permite incrementar o valor de uma chave armazenada na sessão.

```php
$ssn->increment(string $key, int $value);
```

#### Método drop()

Este método permite apagar uma chave existente na sessão.

```php
$ssn->drop(string $key);
```

##### Método dump()

Útil para depuração, este método retorna todos os valores armazenados na sessão.

```php
$ssn->dump(int $format = 1, bool $only_session_key = false)
# $format: formato de retorno dos dados (0 = string | 1 = array (padrão) | 2 = json)
# $only_session_key: true retorna somente os dados da chave de sessão.
#                    false retorna todos os valores armazenados na sessão (padrão)
```

#### Finalizando a sessão

Para finalizar a sessão, utilize o método `end()`.

```php
$ssn->end();
```



## 🤝 Colaborando

Por favor, leia o arquivo [CONDUCT.md][link-conduct] para obter detalhes sobre o nosso código de conduta e o arquivo [CONTRIBUTING.md][link-contributing] para detalhes sobre o processo para nos enviar pedidos de solicitação.

## 📌 Versão

Nós usamos [SemVer][link-semver] para controle de versão.

Para as versões disponíveis, observe as [tags neste repositório][link-tags].

O arquivo [VERSIONS.md][link-versions] possui o histórico de alterações realizadas no projeto.

## ✒ Autores

- **Kadu Velasco** / Desenvolvedor
  - [Perfil][link-profile]
  - [Email][link-email]

## 📄 Licença 

Esse projeto está sob licença MIT. Veja o arquivo [LICENSE][link-license] para mais detalhes ou acesse [mit-license.org](https://mit-license.org/).

[⬆ Voltar ao topo](#zyra-sessions)

<!-- links -->
[link-conduct]:https://github.com/kaduvelasco/zyra-sessions/blob/main/CONDUCT.md
[link-contributing]:https://github.com/kaduvelasco/zyra-sessions/blob/main/CONTRIBUTING.md
[link-license]:https://github.com/kaduvelasco/zyra-sessions/blob/main/LICENSE
[link-versions]:https://github.com/kaduvelasco/zyra-sessions/blob/main/VERSIONS.md
[link-tags]:https://github.com/kaduvelasco/zara-phptools/tags
[link-semver]:http://semver.org/
[link-profile]:https://github.com/kaduvelasco
[link-email]:mailto:kadu.velasco@gmail.com
