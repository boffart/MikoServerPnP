<?php
/**
 * Copyright © MIKO LLC - All Rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 * Written by Alexey Portnov, 8 2019
 */

class MikoServerPnP{
    private $url;
    private $http_port;
    private $pbx_host;
    private $pbx_sip_port;
    private $vm_extension;
    private $feature_transfer;
    private $interfaces;

    private $pbx_version = '1.8';
    private $class_name  = 'MikoServerPnP';
    private $mac_white = [];
    private $mac_black = [];
    private $requests_dir;
    private $config_dir;
    private $debug;

    public function __construct($debug = false){
        $this->debug = ($debug === true);

        $settings_dir = __DIR__.'/settings';
        if(!file_exists($settings_dir) && !mkdir($settings_dir) && !is_dir($settings_dir)){
            $this->sys_log_msg('Can not make dir '.$settings_dir);
        }
        $settings_file = __DIR__.'/settings/settings.json';
        if(!file_exists($settings_file)){
            $this->sys_log_msg('Settings file not found.');
        }
        $settings = json_decode(file_get_contents($settings_file), true);

        $this->http_port        = $settings['http_port']??'';
        $this->pbx_host         = $settings['pbx_host']??'';
        $this->pbx_sip_port     = $settings['pbx_sip_port']??5060;
        $this->vm_extension     = $settings['vm_extension']??'';
        $this->feature_transfer = $settings['feature_transfer']??'';
        $this->interfaces       = $settings['interfaces']??$this->get_interface_names();

        $this->url = str_replace(['<pbx_host>','<http_port>'], [$this->pbx_host,$this->http_port], $settings['url']??'');

        if($this->url === ''){
            $this->sys_log_msg('Not specified configuration url.');
        }

        $re = '/\w{2}:?\w{2}:?\w{2}:?\w{2}:?\w{2}:?\w{2}/m';
        $mac_white_file = __DIR__.'/settings/mac_white.conf';
        if(file_exists($mac_white_file)){
            $mac_white = file_get_contents($mac_white_file);
            preg_match_all($re, strtolower(str_replace(':', '', $mac_white)), $this->mac_white, PREG_SET_ORDER);
            if(count($this->mac_white)>1) {
                $this->mac_white = array_merge(...$this->mac_white);
            }
        }
        $mac_black_file = __DIR__.'/settings/mac_black.conf';
        if(file_exists($mac_black_file)){
            $mac_black = file_get_contents($mac_black_file);
            preg_match_all($re, strtolower(str_replace(':', '', $mac_black)), $this->mac_black, PREG_SET_ORDER);

            if(count($this->mac_black)>1){
                $this->mac_black = array_merge(...$this->mac_black);
            }
        }

        $this->requests_dir = __DIR__.'/requests';
        if(!file_exists($this->requests_dir) && !mkdir($this->requests_dir) && !is_dir($this->requests_dir)){
            $this->sys_log_msg('Can not make dir '.$this->requests_dir);
            $this->requests_dir = __DIR__;
        }
        $this->config_dir   = __DIR__.'/configs';
        if(!file_exists($this->config_dir) && !mkdir($this->config_dir) && !is_dir($this->config_dir)){
            $this->sys_log_msg('Can not make dir '.$this->config_dir);
            $this->config_dir = __DIR__;
        }

        $this->start_http_server();
    }

    /**
     * Имена всех подключенных сетевых интерфейсов.
     */
    public function get_interface_names():array {
        exec('ls /proc/sys/net/ipv4/conf/ | grep eth', $names);
        return $names;
    }


    /**
     * Добавить сообщение в Syslog.
     * @param     $text
     * @param int $level
     */
    private function sys_log_msg($text, $level=null):void {
        openlog($this->class_name, LOG_PID | LOG_PERROR, LOG_AUTH);
        syslog($level ?? LOG_WARNING, $text);
        closelog();
    }

    /**
     * Запуск сервера.
     * @return bool
     */
    public function listen():bool {
        $sock = @socket_create(AF_INET, SOCK_RAW, SOL_UDP);
        if($sock){
            socket_set_option($sock, SOL_SOCKET, SO_REUSEADDR, 1);
            $options = ['group' => '224.0.1.75'];
            foreach ($this->interfaces as $eth){
                $options['interface'] = $eth;
                socket_set_option($sock, IPPROTO_IP, MCAST_JOIN_GROUP, $options);
            }
        }else{
            return FALSE;
        }
        $res = socket_bind($sock, '224.0.1.75', 5060);
        if(!$res){
            return FALSE;
        }

        do {
            if (socket_recv($sock, $packet, 10240, 0)) {
                // Получаем данные пакета.
                $ihl        = ord($packet{0}) & 0xf;
                $payload    = substr($packet, $ihl << 2);
                $row_data   = trim( substr($payload, 8) );
                // Парсим.
                $headers    = $this->parse($row_data);
                if(count($headers)>0){
                    // Отправляем ответ с настройками.
                    $this->send_response($headers);
                }
            }
        } while (true);

        return TRUE;
    }

    /**
     * Старст busybox httpd
     */
    public function start_http_server():void {
        $pid = self::get_pid_process('httpd -p '.$this->http_port);
        file_put_contents('/etc/httpd.conf', "A:*\n.cfg:text/plain\n");
        if($pid === ''){
            exec("busybox httpd -p {$this->http_port} -h {$this->config_dir} -c '/etc/httpd.conf'");
        }
    }

    /**
     * Возвращает PID процесса по его имени.
     * @param        $name
     * @param string $exclude
     * @return string
     */
    public static function get_pid_process($name, $exclude='') :string {
        $filter_cmd = '';
        if(!empty($exclude)){
            $filter_cmd = '| grep -v '.escapeshellarg($exclude);
        }
        $out = array();
        exec("ps -A -o 'pid,args' {$filter_cmd} | grep '$name' | grep -v grep | awk ' {print $1} '", $out);
        return trim(implode(' ', $out));
    }

    /**
     * @param $row_data
     * @return array
     */
    private function parse($row_data):array {

        $this->verbose( "\n $row_data \n");

        $rows    = explode("\n", $row_data);
        if( count($rows)===0 ){
            return [];
        }
        $method = explode(' ', $rows[0])[0];
        if('SUBSCRIBE' !== $method){
            return [];
        }
        $headers = [
            'mac'=>'',
            'phone_ip'=>'',
            'phone_port' => '5060',
            'vendor' => '',
            'model' => ''
        ];
        // В перовй строке смотрим имя SIP сообещния и MAC адрес телефона.
        $headers['method'] = $method;

        $pos_start = strpos($rows[0],'@') - 12;
        $headers['mac']    = strtolower(substr($rows[0], $pos_start, 12));

        if(count($this->mac_white)>0 && !in_array($headers['mac'], $this->mac_white, true)){
            // Если есть белый список, то черный не используем.
            // Провижить можно только белый список.
            return [];
        }

        if(count($this->mac_black)>0 && in_array($headers['mac'], $this->mac_black, true)){
            // Если белый список пуст, то телефоны из черного списка провижить нельзя.
            return [];
        }

        unset($rows[0]);
        foreach ($rows as $row){
            $row = trim($row);
            $h_name = explode(':', $row)[0];
            if('Via' === $h_name){
                // Ищем строку вида 172.16.156.1:53582.
                preg_match_all('/\d+.\d+.\d+.\d+:?\d*/m', $row, $matches, PREG_SET_ORDER);
                if(count($matches) > 0 && count($matches[0]) === 1){
                    $res = explode(':', $matches[0][0]);
                    $headers['phone_ip']      = $res[0];
                    $headers['phone_port']    = $res[1];
                }
                $headers[$h_name] = $row;
            }elseif ('From' === $h_name){
                $headers[$h_name] = $row;
            }elseif ('Call-ID' === $h_name){
                $headers[$h_name] = $row;
            }elseif ('Event' === $h_name){
                $event_data = [];
                // Event: ua-profile;profile-type="device";vendor="Yealink";model="T21D";version="34.72.14.6"
                $res_params = explode(';', strtolower($row));
                foreach ($res_params as $res_param){
                    $arr_param = preg_split('/:\s|=/m', $res_param, -1, PREG_SPLIT_NO_EMPTY);
                    if(!in_array($arr_param[0], ['vendor', 'model', 'version'])){
                        continue;
                    }
                    $event_data[$arr_param[0]] = str_replace('"', '', $arr_param[1]);
                }
                $headers[$h_name] = $event_data;
                $headers["OLD_{$h_name}"] = $row;
            }elseif ('To' === $h_name){
                $headers[$h_name] = $row;
            }
        }

        // Наполним таблицу ARP.
        exec("timeout -t 1 ping {$headers['phone_ip']} -c 1 ");
        // Анализируем MAC адрес устройства.
        exec("busybox arp -D {$headers['phone_ip']} -n | /bin/busybox awk  '{ print $4 }' 2>&1", $out);
        $real_mac = $out[0]??'';
        $real_mac = str_replace(':', '', $real_mac);

        if($real_mac !== $headers['mac']){
            $this->sys_log_msg('The mac address of the device does not match the address in the sip request r_mac: '.$real_mac.' mac: '.$headers['mac']);
        }

        if( !empty($headers['mac']) && !empty($headers['phone_ip']) ){
            $this->sys_log_msg("Request provisiong from ip: {$headers['phone_ip']}; phone: {$headers['Event']['vendor']} {$headers['Event']['model']};");
            file_put_contents($this->requests_dir.'/'.$headers['mac'], json_encode($headers, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
        }

        return $headers;
    }

    /**
     * Отправка SIP ответов на телефон.
     * @param $headers
     */
    public function send_response($headers):void{
        $extension = 'cfg';
        if(isset($headers['Event']) && ($headers['Event']['vendor'] ?? '') === 'snom'){
            $extension = 'xml';
        }
        $sock = socket_create(AF_INET, SOCK_DGRAM, SOL_UDP);
        $msg =  "SIP/2.0 200 OK\r\n".
            "{$headers['Via']}\r\n".
            "Contact: <sip:{$headers['phone_ip']}:{$headers['phone_port']};transport=udp;handler=dum>\r\n".
            "{$headers['To']}\r\n".
            "{$headers['From']}\r\n".
            "{$headers['Call-ID']}\r\n".
            "CSeq: 1 {$headers['method']}\r\n".
            "Expires: 0\r\n".
            "Content-Length: 0\r\n";

        $this->send_to_host($sock, $headers['phone_ip'], (int)$headers['phone_port'], $msg);
        $this->verbose("\n".$msg);
        // $url = "{$this->url}?action=getcfg&mac={$headers['mac']}&".http_build_query($headers['Event']);
        // $url.='&solt='.sha1($headers['mac'].getmypid());
        $url = "{$this->url}{$headers['mac']}.{$extension}";

        $msg =  "NOTIFY sip:{$headers['phone_ip']}:{$headers['phone_port']} SIP/2.0\r\n".
            "{$headers['Via']}\r\n".
            "Max-Forwards: 20\r\n".
            "Contact: <sip:{$headers['phone_ip']}:{$headers['phone_port']};transport=udp;handler=dum>\r\n".
            "{$headers['To']}\r\n".
            "{$headers['From']}\r\n".
            "{$headers['Call-ID']}\r\n".
            "CSeq: 3 NOTIFY\r\n".
            "Content-Type: application/url\r\n".
            "Subscription-State: terminated;reason=timeout\r\n".
            "Event: ua-profile;profile-type=\"device\";vendor=\"MIKO\";model=\"{$this->class_name}\";version=\"{$this->pbx_version}\"\r\n".
            'Content-Length: '.strlen($url)."\r\n".
            "\r\n".
            $url;

        $this->verbose("\n".$msg);
        $this->send_to_host($sock, $headers['phone_ip'], (int)$headers['phone_port'], $msg);
        socket_close($sock);
    }

    private function verbose($msg):void{
        if($this->debug){
            echo($msg);
        }
    }

    /**
     * Отправка SIP сообщения на устрйоство.
     * @param $sock
     * @param $ip
     * @param $port
     * @param $msg
     */
    private function send_to_host($sock, $ip, $port, $msg):void {
        $len = strlen($msg);
        if(@socket_connect($sock, $ip, $port)){
            try{
                $result = @socket_sendto($sock, $msg, $len, 0, $ip, $port);
                if(!$result){
                    usleep(50000);
                    @socket_sendto($sock, $msg, $len, 0, $ip, $port);
                }
            }catch (Exception $e){
                $this->sys_log_msg($e->getPrevious());
            }
        }else{
            $this->sys_log_msg("Host lookup failed $ip:$port...");
        }

    }

    /**
     * Создает конфигурационный файл для Yealink телефона.
     * @param $mac
     * @param $sip_peers
     * @return string
     */
    public function generate_config_yealink($mac, $sip_peers):string {

        $filename = "{$this->config_dir}/{$mac}.cfg";
        $cfg = "#!version:1.0.0.1\r\n";
        foreach ($sip_peers as $line => $sip_peer){
            // Enable or disable the account1, 0-Disabled (default), 1-Enabled;
            $cfg.= "account.{$line}.enable = 1\r\n";
            // Configure the label displayed on the LCD screen for account1.
            $cfg.= "account.{$line}.label = PnP ({$sip_peer['extension']})\r\n";
            // Configure the display name of account1.
            $cfg.= "account.{$line}.display_name = {$sip_peer['callerid']}\r\n";
            // Configure the username and password for register authentication.
            $cfg.= "account.{$line}.auth_name = {$sip_peer['extension']}\r\n";
            $cfg.= "account.{$line}.user_name = {$sip_peer['extension']}\r\n";
            $cfg.= "account.{$line}.password = {$sip_peer['secret']}\r\n";
            $cfg.= "account.{$line}.sip_server_host = {$this->pbx_host}\r\n";
            $cfg.= "account.{$line}.sip_server_port = {$this->pbx_sip_port}\r\n";

            $cfg.= "account.{$line}.transport = 0\r\n";
            $cfg.= "account.{$line}.codec.1.enable = 1\r\n";
            $cfg.= "account.{$line}.codec.1.payload_type = PCMU\r\n";
            $cfg.= "account.{$line}.codec.1.priority = 1\r\n";
            $cfg.= "account.{$line}.codec.1.rtpmap = 0\r\n";
            // Configure the type of SIP header(s) to carry the caller ID;
            // 0-FROM (default), 1-PAI 2-PAI-FROM, 3-PRID-PAI-FROM, 4-PAI-RPID-FROM, 5-RPID-FROM;
            $cfg.= "account.{$line}.cid_source = 4\r\n";
            // Configure the voice mail number of account1.
            $cfg.= "voice_mail.number.{$line} = {$this->vm_extension}\r\n";
        }

        $cfg.= "phone_setting.lcd_logo.mode=0\r\n";
        $cfg.= "auto_provision.dhcp_option.enable = 0\r\n";

        $cfg.="features.intercom.allow = 1\r\n";
        $cfg.="features.intercom.mute = 0\r\n";
        $cfg.="features.intercom.tone = 1\r\n";
        $cfg.="features.intercom.barge = 1\r\n";

        // Configure DTMF sequences. It can be consisted of digits, alphabets, * and #.
        $cfg.="features.dtmf.transfer = {$this->feature_transfer}\r\n";
        // Enable or disable the phone to send DTMF sequences during
        // a call when pressing the transfer soft key or the TRAN key; 0-Disabled (default), 1-Enabled;
        $cfg.="features.dtmf.replace_tran = 1\r\n";
        // Enable or disable the headset prior feature; 0-Disabled (default), 1-Enabled;
        $cfg.="features.headset_prior = 1\r\n";

        file_put_contents($filename, $cfg);
        return $filename;
    }

    /**
     * Создает конфигурационный файл для Snom телефона.
     * @param $mac
     * @param $sip_peers
     * @return string
     */
    public function generate_config_snom($mac, $sip_peers):string {

        $filename = "{$this->config_dir}/{$mac}.xml";
        $cfg = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n";
        $cfg.= '<settings>'."\n";
        $cfg.= '    <phone-settings>'."\n";
        foreach ($sip_peers as $line => $sip_peer){
            $cfg.= "        <user_pname idx=\"{$line}\" perm=\"RW\">{$sip_peer['extension']}</user_pname>\n";
            $cfg.= "        <user_name idx=\"{$line}\" perm=\"RW\">{$sip_peer['extension']}</user_name>\n";
            $cfg.= "        <user_realname idx=\"{$line}\" perm=\"RW\">{$sip_peer['callerid']}</user_realname>\n";
            $cfg.= "        <user_pass idx=\"{$line}\" perm=\"RW\">{$sip_peer['secret']}</user_pass>\n";
            $cfg.= "        <user_host idx=\"{$line}\" perm=\"RW\">{$this->pbx_host}</user_host>\n";
            $cfg.= "        <user_srtp idx=\"{$line}\" perm=\"RW\">off</user_srtp>\n";
            $cfg.= "        <user_mailbox idx=\"{$line}\" perm=\"RW\">{$this->vm_extension}</user_mailbox>\n";
            $cfg.= '        <user_dp_str idx="'.$line.'" perm="RW">!([^#]%2b)#!sip:\1@\d!d</user_dp_str>'."\n";
            $cfg.= '        <contact_source_sip_priority idx="INDEX" perm="PERMISSIONFLAG">PAI RPID FROM</contact_source_sip_priority>'."\n";
        }
        $cfg.= "        <answer_after_policy perm=\"RW\">idle</answer_after_policy>\n";
        $cfg.= '    </phone-settings>'."\n";
        $cfg.= '</settings>'."\n";

        file_put_contents($filename, $cfg);
        return $filename;
    }

    /**
     * Отправка на телефон запроса на перезагрузку.
     * @param $ip_pbx
     * @param $port_pbx
     * @param $ip_phone
     * @param $port_phone
     */
    public static function socket_client_notify($ip_pbx, $port_pbx, $ip_phone, $port_phone):void {
        $phone_user = 'autoprovision_user';
        $sock = socket_create(AF_INET, SOCK_DGRAM, SOL_UDP);

        $msg =  "NOTIFY sip:{$phone_user}@{$ip_phone}:{$port_phone};ob SIP/2.0\r\n".
            "Via: SIP/2.0/UDP {$ip_pbx}:{$port_pbx};branch=z9hG4bK12fd4e5c;rport\r\n".
            "Max-Forwards: 70\r\n".
            "From: \"asterisk\" <sip:asterisk@{$ip_pbx}>;tag=as54cd2be9\r\n".
            "To: <sip:{$phone_user}@{$ip_phone}:{$port_phone};ob>\r\n".
            "Contact: <sip:asterisk@{$ip_pbx}:{$port_pbx}>\r\n".
            "Call-ID: 4afab6ce2bff0be11a4af41064340242@{$ip_pbx}:{$port_pbx}\r\n".
            "CSeq: 102 NOTIFY\r\n".
            "User-Agent: mikopbx\r\n".
            "Allow: INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, SUBSCRIBE, NOTIFY, INFO, PUBLISH, MESSAGE\r\n".
            "Supported: replaces, timer\r\n".
            "Subscription-State: terminated\r\n".
            "Event: check-sync;reboot=true\r\n".
            "Content-Length: 0\r\n\n";

        $len = strlen($msg);
        socket_sendto($sock, $msg, $len, 0, $ip_phone, $port_phone);
        socket_close($sock);
    }

    /**
     * Функция тестирования запущенного PnP сервера. Отправляет SIP запрос на провижинг. 
     * @param $ip
     * @param $port
     * @param $mac
     */
    public static function test_socket_client($ip, $port, $mac):void {
        $sock = socket_create(AF_INET, SOCK_DGRAM, SOL_UDP);
        socket_bind($sock, $ip, $port);

        $resive_sock = @socket_create(AF_INET, SOCK_RAW, SOL_UDP);
        socket_bind($resive_sock, $ip, $port);

        $msg =  "SUBSCRIBE sip:MAC{$mac}@224.0.1.75 SIP/2.0\r\n".
                "Via: SIP/2.0/UDP {$ip}:{$port}.;branch=z9hG4bK42054260\r\n".
                "From: <sip:MAC{$mac}@224.0.1.75>;tag=42054258\r\n".
                "To: <sip:MAC{$mac}@224.0.1.75>\r\n".
                "Call-ID: 42054258@{$ip}\r\n".
                "CSeq: 1 SUBSCRIBE\r\n".
                "Contact: <sip:MAC{$mac}@{$ip}:{$port}>\r\n".
                "Max-Forwards: 70\r\n".
                "User-Agent: Yealink SIP-T21P 34.72.14.6\r\n".
                "Expires: 0\r\n".
                'Event: ua-profile;profile-type="device";vendor="Yealink";model="T21D";version="34.72.14.6"'."\r\n".
                "Accept: application/url\r\n".
                "Content-Length: 0\r\n\n";
        /*
        $msg =  "SUBSCRIBE sip:MAC%3a{$mac}@miko.ru SIP/2.0"."\r\n".
                "Via: SIP/2.0/UDP {$ip}:{$port};rport"."\r\n".
                "From: <sip:MAC%3a{$mac}@miko.ru>;tag=1145111611"."\r\n".
                "To: <sip:MAC%3a{$mac}@miko.ru>"."\r\n".
                'Call-ID: 1913994428@{$ip}'."\r\n".
                'CSeq: 1 SUBSCRIBE'."\r\n".
                'Event: ua-profile;profile-type="device";vendor="snom";model="snomD120";version="10.1.39.11"'."\r\n".
                'Expires: 0'."\r\n".
                'Accept: application/url'."\r\n".
                "Contact: <sip:{$ip}:{$port}>"."\r\n".
                'User-Agent: snomD120/10.1.39.11'."\r\n".
                'Content-Length: 0'."\r\n\n";
        //*/

        $len = strlen($msg);
        socket_sendto($sock, $msg, $len, 0, '224.0.1.75', 5060);
        socket_close($sock);

        do {
            if (socket_recv($resive_sock, $packet, 65536, 0)) {
                // Получаем данные пакета.
                $ihl        = ord($packet{0}) & 0xf;
                $payload    = substr($packet, $ihl << 2);
                $row_data   = trim( substr($payload, 8) );
                // Парсим.
                $rows    = explode("\n", $row_data);
                if( count($rows)<4 ){
                    continue;
                }

                echo "\n{$row_data}\n";
                $method = explode(' ', $rows[0])[0];
                if('NOTIFY' === $method){
                    break;
                }
            }
        } while (true);
        socket_close($resive_sock);
    }
}


if ($argv[1] === 'socket_server') {

    $debug = ($argv[2]??'')==='debug';
    $sn = new MikoServerPnP($debug);
    $sn->listen();
}elseif ($argv[1] === 'socket_client_notify') {

    $ip_pbx     = $argv[2] ?? '127.0.0.1';
    $port_pbx   = (integer) ($argv[3] ?? 5060);
    $ip_phone   = $argv[4] ?? '172.16.32.138';
    $port_phone = (integer) ($argv[5] ?? 5062);
    MikoServerPnP::socket_client_notify($ip_pbx, $port_pbx, $ip_phone, $port_phone);

}elseif ($argv[1] === 'socket_client') {

    $ip   = $argv[2] ?? '127.0.0.1';
    $port = (integer) ($argv[3] ?? 5062);
    $mac  = str_replace(':', '', $argv[4] ?? '0015657322ff');
    MikoServerPnP::test_socket_client($ip, $port, $mac);

}elseif($argv[1] === 'mk_config'){

    $sip_user   = $argv[2]??'';
    $mac        = $argv[4]??'';
    $def_peer = [ 1 => [
        'extension' => $sip_user,
        'secret'    => $argv[3]??'',
        'callerid'  => $sip_user,
    ]];

    $sn = new MikoServerPnP();
    $sn->generate_config_yealink($mac, $def_peer);
    $sn->generate_config_snom($mac, $def_peer);
}elseif($argv[1] === 'help'){

    echo "\n";
    echo 'php -f MikoServerPnP.php socket_client_notify <IP_PBX> <PORT_SIP_PBX> <IP_PHONE> <PORT_PHONE>'."\n";
    echo 'php -f MikoServerPnP.php socket_client_notify 172.16.32.153 5060 172.16.32.148 5060'."\n";
    echo "\n";
    echo 'php -f MikoServerPnP.php socket_server'."\n";
    echo "\n";
    echo 'php -f MikoServerPnP.php socket_client <IP_PHONE> <PORT_PHONE> <MAC_PHONE>'."\n";
    echo 'php -f MikoServerPnP.php socket_client 172.16.156.223 5062 0015657322f1'."\n";
    echo "\n";
    echo 'php -f MikoServerPnP.php mk_config <SIP_ACCAUNT> <SECRET> <MAC>'."\n";
    echo 'php -f MikoServerPnP.php mk_config 203 1792636674b0ddb761b3d0d4713210e5 0015657322ff'."\n";
    echo "\n";

}
