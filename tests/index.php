<?php

/**
 * Zyra Sessions
 *
 * @file     index
 * @author   Kadu Velasco (@kaduvelasco) <kadu.velasco@gmail.com>
 * @url      <https://github.com/kaduvelasco/zyra-sessions>
 * @license  The MIT License (MIT) - <http://opensource.org/licenses/MIT>
 */

declare(strict_types=1);

namespace Zyra;

ini_set('display_errors', '1');
error_reporting(E_ALL);

require_once dirname(__FILE__, 2) . DIRECTORY_SEPARATOR . 'vendor' . DIRECTORY_SEPARATOR . 'autoload.php';

$config = [
    'save_path' => dirname(__FILE__) . DIRECTORY_SEPARATOR . 'cache',
    'auto_start' => false,
    'gc_probability' => 1,
    'gc_divisor' => 100,
    'gc_maxlifetime' => 1800,
    'use_only_cookies' => true,
    'lazy_write' => true,
    'use_strict_mode' => true,
    'sid_length' => 32,
    'sid_bits_per_character' => 5,
    'cookie_lifetime' => 0,
    'cookie_path' => '/',
    'cookie_domain' => $_SERVER['SERVER_NAME'],
    'cookie_secure' => false,
    'cookie_httponly' => true,
    'cookie_samesite' => 'Strict',
    'cache_limiter' => 'public',
    'cache_expires' => 180,
    'session_name' => 'ZyraSession',
    'session_key' => 'ZS',
    'hash_algorithm' => 'sha256',
    'generate_decoy' => true,
    'regenerate_time' => 600,
    'timezone' => 'America/Sao_Paulo',
    'debug' => false,
];

$ssn = new Sessions();
$ssn->setConfig($config);
$ssn->initialize();

$ssn->set('nome', 'Kadu');
$ssn->append('nome', 'Velasco');

$ssn->set('idade', 32);
$ssn->increment('idade', 5);

$ssn->set('teste', 'apagar');
$ssn->drop('teste');

$dump = $ssn->dump();
var_dump($dump);
