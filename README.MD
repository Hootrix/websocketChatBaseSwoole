# 聊天室
简单的聊天室功能，需要服务器安装php swoole扩展。

Demo：http://chat.hhtjim.com

![demo](http://wx2.sinaimg.cn/large/6026770dgy1fcouju4rjpj20ag0flwfk.jpg)


### 服务器端：wsServer.php
基于php扩展`swoole`开发。
代码自swoole官方demo。


### 客户端 ：chat.html  
通过websocke通信

#### 客户端UI  
codepen.io


#### nginx反代参考  
```
server
    {
        listen 80;
        #listen [::]:80;
        server_name chat.hhtjim.com;
        #index index.html index.htm index.php default.html default.htm default.php;
        root  /home/wwwroot/chat.hhtjim.com;

        #include other.conf;
        #error_page   404   /404.html;
        #include enable-php.conf;

        # 访问 ws://chat.hhtjim.com/ 下的内容将被反向代理到http://127.0.0.1:9501
        location /
        {
            proxy_pass http://127.0.0.1:9501;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";
        }

       ...
    }
```
