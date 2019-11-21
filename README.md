# tcp_server_based_on_libevent
## 一个基于libevent的小tcp server，一个基于libevent的小应用，业务代码还没有开始写，只是写了框架，在此做个笔记
## 在自己的2G/i5-8400的虚拟机上简单的测量了下，每秒并发可以达到500
### 设计思路是多线程+I/O多路复用，借鉴了muduo网络库的one loop one thread的思想
主线程只是负责listen fd的处理(accept动作也在此完成)，当主线程的回调函数返回时，connect fd已经知道了，这点libevent帮我们封装的很好。主线程需要做的是
将这个connect fd添加到工作线程的队列里，并且通知工作线程，通知方式是通过管道。工作线程被唤醒后就从自己的队列中取出connect fd，并将其注册成一个event到
自己的event_base上即可。其中需要注意:    1.主线程往工作线程的队列里添加connect fd时的加锁问题，我采用的是双向循环队列，写的时候需要加锁，工作线程读的时候不需要加锁，因为读写分别用的是两个游标。    
2.主线程唤醒工作线程的方式，libevent自带唤醒功能，但是没用那个