<?php
/**
 * Created by PhpStorm.
 * User: pang
 * Date: 17/2/11
 * Time: 18:21
 */

$server = new swoole_websocket_server("0.0.0.0", 9501, SWOOLE_BASE);

$stack = [];//保存5条数据最近5分钟内的数据

//$clients = [];
function user_handshake(swoole_http_request $request, swoole_http_response $response)
{
    //自定定握手规则，没有设置则用系统内置的（只支持version:13的）
    if (!isset($request->header['sec-websocket-key'])) {
        //'Bad protocol implementation: it is not RFC6455.'
        $response->end();
        return false;
    }
    if (0 === preg_match('#^[+/0-9A-Za-z]{21}[AQgw]==$#', $request->header['sec-websocket-key'])
        || 16 !== strlen(base64_decode($request->header['sec-websocket-key']))
    ) {
        //Header Sec-WebSocket-Key is illegal;
        $response->end();
        return false;
    }

    $key = base64_encode(sha1($request->header['sec-websocket-key']
        . '258EAFA5-E914-47DA-95CA-C5AB0DC85B11',
        true));
    $headers = array(
        'Upgrade' => 'websocket',
        'Connection' => 'Upgrade',
        'Sec-WebSocket-Accept' => $key,
        'Sec-WebSocket-Version' => '13',
        'KeepAlive' => 'off',
    );
    foreach ($headers as $key => $val) {
        $response->header($key, $val);
    }
    $response->status(101);
    $response->end();
    global $server;
    $fd = $request->fd;
    $server->defer(function () use ($fd, $server) {
//        $body = [
//            'client' => $fd,
//            'content' => "hello $fd, welcome\n",
//        ];
//        $server->push($fd, json_encode($body));
//        $clients[] = $fd;//添加客户端到容器


        //    握手成功之后写入日志文件
//        write_log($server,$fd);

        $server->push($fd, json_encode([
                'client' => $fd,
                'content' => "hello $fd, welcome",
            ]
        ));

        //发送最近5条消息给新的客户端
        global $stack;
        $now = time();
        foreach ($stack as $k => $v){
            if( $now - $v['time'] > 5 * 60 ){//消息时间 大于5分钟
                unset($stack[$k]);
                continue;
            }
            $server->push($fd, $v['json']);
        }


        //发送给客户端所有客户端数量
        $json = json_encode(['clients' => count($server->connections)]);
        foreach ($server->connections as $item) {
            $server->push($item, $json);
        }

    });
    return true;
}

$server->on('handshake', 'user_handshake');
$server->on('open', function (swoole_websocket_server $_server, swoole_http_request $request) {
//    echo "server#{$_server->worker_pid}: handshake success with fd#{$request->fd}\n";
//    var_dump($_server->exist($request->fd), $_server->getClientInfo($request->fd));
//    var_dump($request);

});

$server->on('message', function (swoole_websocket_server $_server, $frame) {
//    var_dump($frame->data);
//    echo "received " . strlen($frame->data) . " bytes\n";
//    if ($frame->data == "close") {
//        $_server->close($frame->fd);
//    } elseif ($frame->data == "task") {
//        $_server->task(['go' => 'die']);
//    } else {
//        //echo "receive from {$frame->fd}:{$frame->data}, opcode:{$frame->opcode}, finish:{$frame->finish}\n";
//        // for ($i = 0; $i < 100; $i++)
//        {
//            $_send = str_repeat('B', rand(100, 800));
//            $_server->push($frame->fd, $_send);
//            // echo "#$i\tserver sent " . strlen($_send) . " byte \n";
//        }
//        $fd = $frame->fd;
//        $_server->tick(2000, function ($id) use ($fd, $_server) {
//            $_send = str_repeat('B', rand(100, 5000));
//            $ret = $_server->push($fd, $_send);
//            if (!$ret) {
//                var_dump($id);
//                var_dump($_server->clearTimer($id));
//            }
//        });
//    }


    $obj = json_decode($frame->data);
    $content = $obj->content;
    if (empty($content)) return;

    $md5 = $obj->md5;
    $body = [
        'sender' => $frame->fd,//发送消息的客户端   $fd 为接收的客户端
        'content' => htmlspecialchars($content),//尽量防止xss攻击;转换到utf-8 防止json_encode输出为空
        'md5' => htmlspecialchars($md5),
    ];
    $json = json_encode($body);


    global $stack;
    array_push($stack,[//尾进
        'time'=>time(),
        'json'=>json_encode($body),
    ]);

    //只保留5个新的消息内容
    while(count($stack) > 5){
        array_shift($stack);//头出
    }


    foreach ($_server->connections as $fd) {
        $_server->push($fd, $json);
    }
});

$server->on('close', function ($_server, $fd) {
    echo "client {$fd} closed\n";

    $json = json_encode(['clients' => count($_server->connections) - 1,'action'=>'close']);
    foreach ($_server->connections as $item) {
        $_server->push($item, $json);
    }
});

$server->on('task', function ($_server, $worker_id, $task_id, $data) {
    var_dump($worker_id, $task_id, $data);
    return "hello world\n";
});

$server->on('finish', function ($_server, $task_id, $result) {
    var_dump($task_id, $result);
});

$server->on('packet', function ($_server, $data, $client) {
    echo "#" . posix_getpid() . "\tPacket {$data}\n";
    var_dump($client);
});

$server->on('request', function (swoole_http_request $request, swoole_http_response $response) {
    global $chatHtml;
    $response->end($chatHtml);
//    $response->end(<<<HTML
//
//HTML
//    );
});
$chatHtml = file_get_contents(dirname(__FILE__) . '/chat.html');
$server->start();


/**
 * 检查log目录 删除多余
 * 保留最近指定数量的文件
 *
 * @param $dir 目录
 * @param int $limit 保留时间最近的文件数
 */
function checkDeleteLogFile($dir, $limit = 10)
{
    $lscanLst = scandir($dir);
    if ($lscanLst) {
        $lscanLst = array_diff($lscanLst, ['.', '..']);
        $total = count($lscanLst);
        if ($total > $limit) {//若文件数量 较限制数大
            usort($lscanLst, function ($a, $b) {
                preg_match('/\d+/', $a, $_a);
                preg_match('/\d+/', $b, $_b);
                $a = $_a[0];
                $b = $_b[0];
                return $a - $b;//从小到大排序
            });

            for ($i = 0; $i < $total - $limit; $i++) {//删除多余文件
                unlink($dir . '/' . $lscanLst[$i]);
            }
        }
    }
}

function write_log($server,$fd){
    $array = [
        'worker_pid' => $server->worker_pid,
        'fd' => $fd,
    ];
    $data = json_encode($array) . "\n";
    if (!file_exists(dirname(__FILE__) . '/logs')) mkdir(dirname(__FILE__) . '/logs', 0700);
    checkDeleteLogFile(dirname(__FILE__) . '/logs');
    file_put_contents(dirname(__FILE__) . "/logs/open-" . date('Ymd') . ".logs", $data, FILE_APPEND);
}

