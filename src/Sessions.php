<?php

/**
 * Zyra Sessions
 *
 * @package  Sessions
 * @author   Kadu Velasco (@kaduvelasco) <kadu.velasco@gmail.com>
 * @url      <https://github.com/kaduvelasco/zyra-sessions>
 * @license  The MIT License (MIT) - <http://opensource.org/licenses/MIT>
 */

declare(strict_types=1);

namespace Zyra;

class Sessions
{
    /**
     * @var string|null
     */
    private ?string $save_path = null;

    /**
     * @var bool
     */
    private bool $auto_start = false;

    /**
     * @var int
     */
    private int $gc_probability = 1;

    /**
     * @var int
     */
    private int $gc_divisor = 100;

    /**
     * @var int
     */
    private int $gc_maxlifetime = 1800;

    /**
     * @var bool
     */
    private bool $use_only_cookies = true;

    /**
     * @var bool
     */
    private bool $lazy_write = true;

    /**
     * @var bool
     */
    private bool $use_strict_mode = true;

    /**
     * @var int
     */
    private int $sid_length = 32;

    /**
     * @var int
     */
    private int $sid_bits_per_character = 5;

    /**
     * @var int
     */
    private int $cookie_lifetime = 0;

    /**
     * @var string
     */
    private string $cookie_path = '/';

    /**
     * @var string
     */
    private string $cookie_domain = 'change';

    /**
     * @var bool
     */
    private bool $cookie_secure = false;

    /**
     * @var bool
     */
    private bool $cookie_httponly = true;

    /**
     * @var string
     */
    private string $cookie_samesite = 'Strict';

    /**
     * @var string
     */
    private string $cache_limiter = 'public';

    /**
     * @var int
     */
    private int $cache_expires = 180;

    /**
     * @var string
     */
    private string $session_name = 'ZyraSession';

    /**
     * @var string
     */
    private string $session_key = 'ZS';

    /**
     * @var string
     */
    private string $hash_algorithm = 'sha256';

    /**
     * @var bool
     */
    private bool $generate_decoy = true;

    /**
     * @var int
     */
    private int $regenerate_time = 600;

    /**
     * @var string
     */
    private string $timezone = 'America/Sao_Paulo';

    /**
     * @var bool
     */
    private bool $debug = false;

    /**
     * @param array<mixed>|null $config
     *
     * Construtor da classe.
     */
    public function __construct(?array $config = null)
    {
        if (!is_null($config)) {
            $this->setConfig($config);
        }

        if ($this->cookie_domain == 'change') {
            $this->cookie_domain = $_SERVER['SERVER_NAME'];
        }
    }

    /**
     * Impede o clone da classe.
     */
    private function __clone()
    {
        die('This class cannot be cloned.');
    }

    /**
     * Define as configurações a partir de um array.
     *
     * @param array<mixed> $options
     *
     * @return void
     */
    public function setConfig(array $options): void
    {
        foreach ($options as $k => $v) {
            switch ($k) {
                case 'save_path':
                    $this->setSavePath($v);
                    break;
                case 'auto_start':
                    $this->setAutoStart($v);
                    break;
                case 'gc_probability':
                    $this->setGcProbability($v);
                    break;
                case 'gc_divisor':
                    $this->setGcDivisor($v);
                    break;
                case 'gc_maxlifetime':
                    $this->setGcMaxLifetime($v);
                    break;
                case 'use_only_cookies':
                    $this->setUseOnlyCookies($v);
                    break;
                case 'lazy_write':
                    $this->setLazyWrite($v);
                    break;
                case 'use_strict_mode':
                    $this->useStrictMode($v);
                    break;
                case 'sid_length':
                    $this->setSidLength($v);
                    break;
                case 'sid_bits_per_character':
                    $this->setSidBitsPerCharacter($v);
                    break;
                case 'cookie_lifetime':
                    $this->setCookieLifetime($v);
                    break;
                case 'cookie_path':
                    $this->setCookiePath($v);
                    break;
                case 'cookie_domain':
                    $this->setCookieDomain($v);
                    break;
                case 'cookie_secure':
                    $this->setCookieSecure($v);
                    break;
                case 'cookie_httponly':
                    $this->setCookieHttpOnly($v);
                    break;
                case 'cookie_samesite':
                    $this->setCookieSameSite($v);
                    break;
                case 'cache_limiter':
                    $this->setcacheLimiter($v);
                    break;
                case 'cache_expires':
                    $this->setCacheExpires($v);
                    break;
                case 'session_name':
                    $this->setSessionName($v);
                    break;
                case 'session_key':
                    $this->setSessionKey($v);
                    break;
                case 'hash_algorithm':
                    $this->setHashAlgorithm($v);
                    break;
                case 'generate_decoy':
                    $this->setGenerateDecoy($v);
                    break;
                case 'regenerate_time':
                    $this->setRegenerateTime($v);
                    break;
                case 'timezone':
                    $this->setTimezone($v);
                    break;
                case 'debug':
                    $this->setDebug($v);
                    exit();
            }
        }
    }

    /**
     * Diretório onde as sessões serão salvas.
     * Precisa ser um diretório válido com permissão de escrita.
     *
     * @param string|null $save_path
     *
     * @return void
     */
    public function setSavePath(?string $save_path): void
    {
        if (!is_null($save_path)) {
            if (!is_dir($save_path) || (!is_writable($save_path))) {
                die('The directory for storing sessions does not exist or does not have the necessary permissions.');
            }
        }
        $this->save_path = $save_path;
    }

    /**
     * Define se as sessões serão iniciadas automaticamente.
     *
     * @param bool $auto_start
     *
     * @return void
     */
    public function setAutoStart(bool $auto_start): void
    {
        $this->auto_start = $auto_start;
    }

    /**
     * Em conjunto com o gc_divisor, calcula a porcentagem de chance do GC (coletor de lixo)
     * ser chamado na inicialização da sessão.
     *
     * @param int $probability
     *
     * @return void
     */
    public function setGcProbability(int $probability): void
    {
        $this->gc_probability = $probability;
    }

    /**
     * Em conjunto com o gc_probability, calcula a porcentagem de chance do GC (coletor de lixo)
     * ser chamado na inicialização da sessão.
     *
     * @param int $divisor
     *
     * @return void
     */
    public function setGcDivisor(int $divisor): void
    {
        $this->gc_divisor = $divisor;
    }

    /**
     * Tempo, em segundos que os dados são considerados "lixo" e enviados ao GC.
     *
     * @param int $max_lifetime
     *
     * @return void
     */
    public function setGcMaxLifetime(int $max_lifetime): void
    {
        $this->gc_maxlifetime = $max_lifetime;
    }

    /**
     * Define se só será utilizado “cookies” para guardar o ID no lado do cliente.
     * Previne ataques envolvendo passagem de IDs de sessão nas URLs.
     *
     * @param bool $only_cookies
     *
     * @return void
     */
    public function setUseOnlyCookies(bool $only_cookies): void
    {
        $this->use_only_cookies = $only_cookies;
    }

    /**
     * Define se os dados só serão reescritos em caso de mudança.
     *
     * @param bool $lazy_write
     *
     * @return void
     */
    public function setLazyWrite(bool $lazy_write): void
    {
        $this->lazy_write = $lazy_write;
    }

    /**
     * Define se os métodos de sessão serão rigorosos (strict).
     *
     * @param bool $strict_mode
     *
     * @return void
     */
    public function useStrictMode(bool $strict_mode): void
    {
        $this->use_strict_mode = $strict_mode;
    }

    /**
     * Tamanho do texto da "id de sessão". Deve estar no intervalo de 22 até 256
     *
     * @param int $length
     *
     * @return void
     */
    public function setSidLength(int $length): void
    {
        if (in_array($length, range(22, 256))) {
            $this->sid_length = $length;
        } else {
            die('The length of the session ID is invalid. Must be a value between 22 and 256.');
        }
    }

    /**
     * Número de bits codificados no ID de sessão. São possíveis:
     * * 4: (0 – 9,a-f)
     * * 5: (0 – 9,a-v)
     * * 6: (0 – 9,a-z, A-Z,'-',',')
     *
     * @param int $bits
     *
     * @return void
     */
    public function setSidBitsPerCharacter(int $bits): void
    {
        if (in_array($bits, range(4, 6))) {
            $this->sid_bits_per_character = $bits;
        } else {
            die('Number of bits encoded in Session ID is invalid. It should be 4, 5 or 6.');
        }
    }

    /**
     * Define o tempo de vida, em segundos, do cookie. O valor zero define até o fechamento do navegador.
     *
     * @param int $lifetime
     *
     * @return void
     */
    public function setCookieLifetime(int $lifetime): void
    {
        $this->cookie_lifetime = $lifetime;
    }

    /**
     * Define o caminho para definir em session_cookie.
     *
     * @param string $path
     *
     * @return void
     */
    public function setCookiePath(string $path): void
    {
        $this->cookie_path = $path;
    }

    /**
     * Define o domínio para definir no cookie de sessão.
     *
     * @param string $domain
     *
     * @return void
     */
    public function setCookieDomain(string $domain): void
    {
        $this->cookie_domain = $domain;
    }

    /**
     * Define se o cookie será enviado apenas em conexões seguras.
     *
     * @param bool $secure
     *
     * @return void
     */
    public function setCookieSecure(bool $secure): void
    {
        $this->cookie_secure = $secure;
    }

    /**
     * Define se o cookie será acessível apenas pelo protocolo HTTP.
     * Reduz o roubo de identidade através de ataques XSS.
     *
     * @param bool $http_only
     *
     * @return void
     */
    public function setCookieHttpOnly(bool $http_only): void
    {
        $this->cookie_httponly = $http_only;
    }

    /**
     * Cookie deve ou não ser enviado em solicitações entre sites.
     * Reduz o risco de vazamento de informações de origem cruzada.
     *
     * @param string $samesite
     *
     * @return void
     */
    public function setCookieSameSite(string $samesite): void
    {
        if (in_array($samesite, ['Strict', 'Lax'])) {
            $this->cookie_samesite = $samesite;
        } else {
            die('The cache.samesite value is invalid. Must be "Strict" or "Lax".');
        }
    }

    /**
     * Limitador do cache atual.
     *
     * @param string $limiter
     *
     * @return void
     */
    public function setCacheLimiter(string $limiter): void
    {
        if (in_array($limiter, ['public', 'private_no_expire', 'private', 'nocache'])) {
            $this->cache_limiter = $limiter;
        } else {
            die('The cache.limiter value is invalid. Must be "public", "private_no_expire", "private" or "nocache".');
        }
    }

    /**
     * Tempo em que o cache irá expirar.
     *
     * @param int $expires
     */
    public function setCacheExpires(int $expires): void
    {
        $this->cache_expires = $expires;
    }

    /**
     * Define o nome da sessão.
     *
     * @param string $session_name
     *
     * @return void
     */
    public function setSessionName(string $session_name): void
    {
        $this->session_name = $session_name;
    }

    /**
     * Define a chave do array da sessão que será utilizada.
     *
     * @param string $session_key
     *
     * @return void
     */
    public function setSessionKey(string $session_key): void
    {
        $this->session_key = $session_key;
    }

    /**
     * Define o método de hash utilizado na classe.
     * Deve ser um método disponível no servidor.
     *
     * @param string $hash_algorithm
     *
     * @return void
     */
    public function setHashAlgorithm(string $hash_algorithm): void
    {
        if (in_array($hash_algorithm, hash_algos())) {
            $this->hash_algorithm = $hash_algorithm;
        } else {
            die('The server does not support the hash algorithm provided.');
        }
    }

    /**
     * Define se um cookie "isca" será criado.
     *
     * @param bool $generate_decoy
     */
    public function setGenerateDecoy(bool $generate_decoy): void
    {
        $this->generate_decoy = $generate_decoy;
    }

    /**
     * Tempo, em segundo que será adicionado sempre que uma sessão for regenerada.
     *
     * @param int $time
     *
     * @return void
     */
    public function setRegenerateTime(int $time): void
    {
        $this->regenerate_time = $time;
    }

    /**
     * Define o fuso horário.
     *
     * @param string $timezone
     *
     * @return void
     */
    public function setTimezone(string $timezone): void
    {
        $this->timezone = $timezone;
    }

    /**
     * Define o status de debug.
     *
     * @param bool $debug
     *
     * @return void
     */
    public function setDebug(bool $debug): void
    {
        $this->debug = $debug;
    }

    /**
     * Inicia a sessão
     *
     * @param bool $restart
     *
     * @return void
     */
    public function initialize(bool $restart = false): void
    {
        if ($restart) {
            $this->regenerateId();
        } else {
            $this->configureSession();
        }

        // Gera a sessão
        $this->generateSystemSession();

        if ($restart) {
            $this->setFingerprint();
            $this->resetLifespan();
        }

        if ($this->validateFingerprint()) {
            $this->generateDecoyCookie();
            $this->checkLifespan();
            $this->set('session_loaded', date('U'));
            $this->set('ttl', ($this->get('lifespan') - $this->get('session_loaded')));
        }

        $this->verifySettings();
    }

    /**
     * Cria o valor da sessão se não existir, caso contrário, o valor será atualizado.
     *
     * @param string $key   Nome da variável de sessão para criar/atualizar
     * @param mixed  $value Valor da variável de sessão para criar/atualizar
     * @param bool   $hash  false = armazenar $value na matriz da sessão como texto simples,
     *                      true = armazenar hash de $value na matriz de sessão
     *
     * @return void
     */
    public function set(string $key, $value, bool $hash = false): void
    {
        if ($hash) {
            $value = hash($this->$this->hash_algorithm, $value);
        }

        $_SESSION[$this->session_key][$key] = $value;
    }

    /**
     * Retorna o valor da variável de sessão. Null se não existir.
     *
     * @param string $key
     *
     * @return mixed
     */
    public function get(string $key)
    {
        return (isset($_SESSION[$this->session_key][$key]))
            ? $_SESSION[$this->session_key][$key]
            : null;
    }

    /**
     * Anexar ao valor da sessão.
     * Observação: o comportamento do acréscimo varia conforme o tipo do valor atual:
     * * Array: valor passado adicionado ao array (array_merge)
     * * String: valor passado adicionado ao final da string (concatenação)
     * * Outro: o valor passado substitui o valor salvo (substituir)
     *
     * @param string $key   Nome da variável de sessão para criar/atualizar
     * @param mixed $value
     *
     * @return void
     */
    public function append(string $key, $value): void
    {
        $current_value = $this->get($key);

        if (isset($current_value)) {
            if (is_array($current_value)) {
                $updated_value = array_merge($current_value, $value);
            } elseif (is_string($current_value)) {
                $updated_value = $current_value . $value;
            } else {
                $updated_value = $value;
            }
        } else {
            $updated_value = $value;
        }

        $this->set($key, $updated_value);
    }

    /**
     * Aumente o valor da variável armazenada na sessão.
     *
     * @param string $key Nome da variável de sessão para criar/incrementar
     * @param int $value  Quantidade a adicionar ao valor atual
     *
     * @return void
     */
    public function increment(string $key, int $value): void
    {
        if (!is_numeric($value)) {
            die(sprintf('Only numeric values can be passed to %s', __METHOD__));
        }

        $current_value = $this->get($key);

        if (isset($current_value)) {
            $updated_value = $current_value + $value;
        } else {
            $updated_value = $value;
        }

        $this->set($key, $updated_value);
    }

    /**
     * Apaga um valor da sessão.
     *
     * @param string $key
     *
     * @return void
     */
    public function drop(string $key): void
    {
        unset($_SESSION[$this->session_key][$key]);
    }

    /**
     * Retorna os valores armazenados na sessão. Útil para depuração.
     *
     * @param int $format 0 = string
     *                    1 = array
     *                    2 = json encoded string
     * @param bool $only_session_key Retorna somente os valores da chave da sessão
     *
     * @return array<mixed>|bool|string|void
     */
    public function dump(int $format = 1, bool $only_session_key = false)
    {
        if (!in_array($format, [1, 2, 3])) {
            die('The format provided for the dump is not valid. Must be 0 (string), 1 (array) or 2 (json).');
        }

        $arr_return = ($only_session_key) ? $_SESSION[$this->session_key] : $_SESSION;

        switch ($format) {
            case 1:
                return print_r($arr_return, true);
            case 2:
                return $arr_return;
            case 3:
            default:
                return json_encode($arr_return);
        }
    }

    /**
     * Finaliza a sessão.
     *
     * @return void
     */
    public function end(): void
    {
        session_unset();
        session_destroy();
    }

    /**
     * Define as configurações de session e cookie.
     * @see https://www.php.net/manual/en/session.configuration.php
     *
     * @return void
     */
    private function configureSession(): void
    {
        // Caminho onde as sessões serão salvas.
        if (!is_null($this->save_path)) {
            ini_set('session.save_path', $this->save_path);
            session_save_path($this->save_path);
        }

        // As sessões não são iniciadas automaticamente
        ini_set('session.auto_start', ($this->auto_start) ? '1' : '0');

        // Probabilidade do coletor de lixo (GC) seja iniciado.
        ini_set('session.gc_probability', strval($this->gc_probability));
        ini_set('session.gc_divisor', strval($this->gc_divisor));

        // Tempo, em segundos que os dados são considerados "lixo" e enviados ao GC.
        // Padrão: 30 minutos.
        ini_set('session.gc_maxlifetime', strval($this->gc_maxlifetime));

        // Só será utilizado cookies para guardar o ID no lado do cliente.
        // Previne ataques envolvendo passagem de IDs de sessão nas URLs.
        ini_set('session.use_only_cookies', ($this->use_only_cookies) ? '1' : '0');

        // Os dados de sessão só será reescrito caso mudem.
        ini_set('session.lazy_write', ($this->lazy_write) ? '1' : '0');

        // Utiliza o modo de sessão rigoroso (strict).
        ini_set('session.use_strict_mode', ($this->use_strict_mode) ? '1' : '0');

        // Configura o ID de sessão forte.
        ini_set('session.sid_length', strval($this->sid_length));
        ini_set('session.sid_bits_per_character', strval($this->sid_bits_per_character));

        // Tempo de vida do cookie, em segundos. Zero = até o navegador ser fechado.
        ini_set('session.cookie_lifetime', strval($this->cookie_lifetime));

        // Caminho para definir em session_cookie.
        ini_set('session.cookie_path', $this->cookie_path);

        // Domínio para definir no cookie de sessão.
        ini_set('session.cookie_domain', $this->cookie_domain);

        // Especifica se os cookies devem ser enviados apenas em conexões seguras.
        ini_set('session.cookie_secure', ($this->cookie_secure) ? '1' : '0');

        // O cookie é acessível somente pelo protocolo HTTP.
        // Reduz o roubo de identidade através de ataque XSS.
        ini_set('session.cookie_httponly', ($this->cookie_httponly) ? '1' : '0');

        // Cookie deve ou não ser enviado em solicitações entre sites.
        // Reduz o risco de vazamento de informações de origem cruzada.
        ini_set('session.cookie_samesite', $this->cookie_samesite);
    }

    /**
     * Gera a sessão.
     *
     * @return void
     */
    private function generateSystemSession(): void
    {
        session_set_cookie_params(
            $this->cookie_lifetime,
            $this->cookie_path,
            $this->cookie_domain,
            $this->cookie_secure,
            $this->cookie_httponly
        );

        session_name($this->session_name);
        session_cache_limiter($this->cache_limiter);
        session_cache_expire($this->cache_expires);

        if (!is_null($this->save_path)) {
            session_save_path($this->save_path);
        }

        session_start();

        // Inicia a sessão com a chave definida.
        if (!isset($_SESSION[$this->session_key])) {
            $_SESSION[$this->session_key] = [];
        }
    }

    /**
     * Regenera o id da sessão.
     */
    private function regenerateId(): void
    {
        session_regenerate_id(true);
        $new_id = session_id();
        session_write_close();

        /** @phpstan-ignore-next-line */
        session_id($new_id);
    }

    /**
     * Cria uma identificação da sessão a partir do agente do usuário, ip e id da sessão
     * em uma tentativa de desencorajar o sequestro de sessão.
     *
     * @return void
     */
    private function setFingerprint(): void
    {
        $this->set('fingerprint', $this->generateFingerprint());
    }

    /**
     * Gerar hash de identificação a partir das configurações atuais.
     *
     * @return string
     */
    protected function generateFingerprint(): string
    {
        return hash(
            $this->hash_algorithm,
            $_SERVER['HTTP_USER_AGENT'] . $_SERVER['REMOTE_ADDR'] . session_id()
        );
    }

    /**
     * Redefina o tempo de vida da sessão usando um valor aleatório entre timeMin e timeMax.
     *
     * @return void
     */
    protected function resetLifespan(): void
    {
        $this->set('lifespan', date('U') + $this->regenerate_time);
    }

    /**
     * Compare o agente do usuário atual, o ip e o id da sessão com a identificação da sessão armazenada
     * Se o valor comparado não corresponder ao valor armazenado, encerre a sessão.
     *
     * @return bool Valid fingerprint
     */
    protected function validateFingerprint(): bool
    {
        $print = $this->get('fingerprint');
        $valid = $this->generateFingerprint();

        if (is_null($print)) {
            $this->setFingerprint();
        } elseif ($print !== $valid) {
            $this->end();
            return false;
        }
        return true;
    }

    /**
     * Cria um cookie "isca" caso ainda não tenha sido definido.
     *
     * Este cookie exibe intencionalmente sinais de um cookie de sessão para parecer
     * interessante para pessoal mal intencionadas. Essas vulnerabilidades incluem:
     * * nome PHPSESSID
     * * valor hash MD5
     * * HTTPOnly como falso
     *
     * @return void
     */
    protected function generateDecoyCookie()
    {
        $has_decoy = isset($_COOKIE['PHPSESSID']);

        if ($this->generate_decoy && !$has_decoy) {
            $this->set('decoy_value', md5((string)mt_rand()));
            setcookie(
                'PHPSESSID',
                $this->get('decoy_value'),
                0,
                $this->cookie_path,
                $this->cookie_domain,
                $this->cookie_secure,
                false
            );
        }
    }

    /**
     * Compare o tempo de vida da sessão com o tempo atual
     * Se a hora atual estiver além do tempo de vida da sessão, gere a id da sessão.
     *
     * @return void
     */
    protected function checkLifespan(): void
    {
        if (empty($this->get('lifespan'))) {
            $this->resetLifespan();
        } elseif ($this->get('lifespan') < date('U')) {
            // Reinicia a sessão
            $this->initialize(true);
        }
    }

    /**
     * Valida as configurações
     *
     * @return void
     */
    protected function verifySettings(): void
    {
        $this->validateSystemTimezone();

        if ($this->debug) {
            $this->validatePHPVersion();
            $this->validateSessionDomain();
        }
    }

    /**
     * Caso o fuso horário não esteja definido, defina-o se possível.
     *
     * @return void
     */
    private function validateSystemTimezone()
    {
        if (function_exists('ini_get') && ini_get('date.timezone') == '') {
            date_default_timezone_set($this->timezone);
        }
    }

    /**
     * Confirme se a versão do PHP é pelo menos 7.4.0
     *
     * @return void
     */
    private function validatePHPVersion()
    {
        if (version_compare(phpversion(), '7.4.0', '<')) {
            die('Zyra Sessions class needs PHP at minimum version 7.4.0');
        }
    }

    /**
     * Confirm that request domain matches cookie domain.
     *
     * @return void
     */
    private function validateSessionDomain()
    {
        if ($_SERVER['HTTP_HOST'] != $this->cookie_domain) {
            die(sprintf(
                'Session cookie domain (%s) and request domain (%s) do not match.',
                $_SERVER['HTTP_HOST'],
                $this->cookie_domain
            ));
        }
    }
}
