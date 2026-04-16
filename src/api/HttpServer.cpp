/**
 * @file HttpServer.cpp
 * @brief HTTP 服务器实现 (M4.2.3I)
 */

#include "HttpServer.h"

#include <QFuture>
#include <QAbstractSocket>
#include <QHttpHeaders>
#include <QHttpServerRequest>
#include <QHttpServerResponse>
#include <QHttpServerResponder>
#include <QTcpServer>
#include <QUrlQuery>
#include <QtConcurrent>

#include "dto/HttpTypes.h"
#include "log/Logger.h"

namespace wekey {
namespace api {

namespace {
const QByteArray kJsonContentType = "application/json; charset=utf-8";
const QByteArray k404Body = R"({"code":404,"message":"not found","data":null})";
}  // namespace

HttpServer::HttpServer(QObject* parent)
    : QObject(parent), server_(new QHttpServer(this)) {}

HttpServer::~HttpServer() {
    if (running_) {
        stop();
    }
}

Result<void> HttpServer::start(int port) {
    if (running_) {
        return Result<void>::err(
            Error(Error::Fail, "服务器已在运行", "HttpServer::start"));
    }

    auto setupResult = ensureTcpServerReady();
    if (setupResult.isErr()) {
        return setupResult;
    }

    if (tcpServer_->isListening()) {
        LOG_WARN(QString("[HttpServer] 启动前发现 QTcpServer 仍处于监听状态，先执行 close，port=%1")
                     .arg(tcpServer_->serverPort()));
        tcpServer_->close();
    }

    // 确保端口独占绑定，防止其他程序复用端口
    // 注意：在 macOS 上，QTcpServer 默认行为已经是独占的
    // 但我们显式记录这一点以便调试
    if (!tcpServer_->listen(QHostAddress::Any, static_cast<quint16>(port))) {
        QString errorMsg = tcpServer_->errorString();
        LOG_ERROR(QString("[HttpServer] 监听失败，port=%1，error=%2").arg(port).arg(errorMsg));
        return Result<void>::err(
            Error(Error::PortInUse,
                  QString("监听端口 %1 失败：%2").arg(port).arg(errorMsg),
                  "HttpServer::start"));
    }

    // QHttpServer::bind 要求底层 QTcpServer 已处于 listening 状态。
    // 上一版把 bind 提前到了 ensureTcpServerReady()，会在 listen() 前触发：
    // "The TCP server ... is not listening."
    // 因此这里必须在 listen() 成功后再做一次性绑定。
    if (!serverBound_) {
        serverBound_ = server_->bind(tcpServer_);
        if (!serverBound_) {
            QString errorMsg = tcpServer_->errorString();
            LOG_ERROR(QString("[HttpServer] QHttpServer 绑定 QTcpServer 失败，port=%1，error=%2")
                          .arg(port)
                          .arg(errorMsg));
            tcpServer_->close();
            return Result<void>::err(
                Error(Error::Fail,
                      QString("QHttpServer 绑定 QTcpServer 失败：%1").arg(errorMsg),
                      "HttpServer::start"));
        }
        LOG_INFO(QString("[HttpServer] QHttpServer 已绑定到底层 QTcpServer，port=%1").arg(port));
    }

    running_ = true;
    port_ = port;
    LOG_INFO(QString("[HttpServer] 已启动监听，port=%1").arg(port));

    emit started(port);
    return Result<void>::ok();
}

void HttpServer::stop() {
    if (!running_) {
        LOG_DEBUG("[HttpServer] stop() 被调用，但服务器当前未运行");
        return;
    }

    if (tcpServer_) {
        LOG_INFO(QString("[HttpServer] 正在停止监听，port=%1，isListening=%2")
                     .arg(port_)
                     .arg(tcpServer_->isListening()));
        if (tcpServer_->isListening()) {
            // 只停止接受新连接，不再直接 delete QTcpServer：
            // QHttpServer 已绑定该对象，若请求/连接尚在清理中，强删底层 socket 对象
            // 容易在 macOS 上触发 notifier 清理时序异常。
            tcpServer_->close();
        }
    }

    running_ = false;
    port_ = 0;
    LOG_INFO("[HttpServer] 已停止监听");

    emit stopped();
}

bool HttpServer::isRunning() const {
    return running_;
}

int HttpServer::port() const {
    return port_;
}

Result<void> HttpServer::ensureTcpServerReady() {
    if (!tcpServer_) {
        tcpServer_ = new QTcpServer(this);
        tcpServer_->setMaxPendingConnections(512);

        connect(tcpServer_, &QTcpServer::newConnection, this, [this]() {
            LOG_DEBUG(QString("[HttpServer] 接收到新连接，listening=%1，port=%2")
                          .arg(tcpServer_ && tcpServer_->isListening())
                          .arg(tcpServer_ ? tcpServer_->serverPort() : 0));
        });
        connect(tcpServer_, &QTcpServer::acceptError, this,
                [this](QAbstractSocket::SocketError socketError) {
                    QString errorText = tcpServer_ ? tcpServer_->errorString() : QString("tcpServer is null");
                    LOG_ERROR(QString("[HttpServer] acceptError=%1，error=%2")
                                  .arg(static_cast<int>(socketError))
                                  .arg(errorText));
                });
        connect(tcpServer_, &QObject::destroyed, this, []() {
            LOG_DEBUG("[HttpServer] QTcpServer 对象已销毁");
        });

        LOG_INFO("[HttpServer] 已创建底层 QTcpServer");
    }

    return Result<void>::ok();
}

void HttpServer::appendCorsHeaders(QHttpHeaders& headers) {
    headers.append(QHttpHeaders::WellKnownHeader::AccessControlAllowOrigin, "*");
    headers.append(QHttpHeaders::WellKnownHeader::AccessControlAllowMethods,
                   "GET, POST, PUT, DELETE, PATCH, OPTIONS");
    headers.append(QHttpHeaders::WellKnownHeader::AccessControlAllowHeaders,
                   "Content-Type, Authorization, X-Requested-With");
    headers.append(QHttpHeaders::WellKnownHeader::AccessControlMaxAge, "86400");
}

HttpRequest HttpServer::parseHttpRequest(const QHttpServerRequest& req) {
    HttpRequest httpReq;
    httpReq.path = req.url().path();
    httpReq.body = QString::fromUtf8(req.body());

    switch (req.method()) {
        case QHttpServerRequest::Method::Get:     httpReq.method = HttpMethod::GET; break;
        case QHttpServerRequest::Method::Post:    httpReq.method = HttpMethod::POST; break;
        case QHttpServerRequest::Method::Put:     httpReq.method = HttpMethod::PUT; break;
        case QHttpServerRequest::Method::Delete:  httpReq.method = HttpMethod::DELETE; break;
        case QHttpServerRequest::Method::Patch:   httpReq.method = HttpMethod::PATCH; break;
        case QHttpServerRequest::Method::Head:    httpReq.method = HttpMethod::HEAD; break;
        case QHttpServerRequest::Method::Options: httpReq.method = HttpMethod::OPTIONS; break;
        default:                                  httpReq.method = HttpMethod::GET; break;
    }

    QUrlQuery urlQuery(req.url());
    for (const auto& item : urlQuery.queryItems()) {
        httpReq.queryParams[item.first] = item.second;
    }

    const auto& headers = req.headers();
    for (qsizetype i = 0; i < headers.size(); ++i) {
        httpReq.headers[QString(headers.nameAt(i))] =
            QString::fromUtf8(headers.valueAt(i));
    }

    return httpReq;
}

QHttpServerRequest::Methods HttpServer::toQtMethod(HttpMethod method) {
    switch (method) {
        case HttpMethod::GET:    return QHttpServerRequest::Method::Get;
        case HttpMethod::POST:   return QHttpServerRequest::Method::Post;
        case HttpMethod::PUT:    return QHttpServerRequest::Method::Put;
        case HttpMethod::DELETE: return QHttpServerRequest::Method::Delete;
        case HttpMethod::PATCH:  return QHttpServerRequest::Method::Patch;
        case HttpMethod::HEAD:   return QHttpServerRequest::Method::Head;
        default:                 return QHttpServerRequest::Method::Get;
    }
}

void HttpServer::setRouter(ApiRouter* router) {
    router_ = router;

    // 1. 为所有 route() 响应全局注入 CORS 头
    // addAfterRequestHandler 仅对 route() 注册的路由生效，不影响 setMissingHandler
    server_->addAfterRequestHandler(server_,
        [](const QHttpServerRequest&, QHttpServerResponse& resp) {
            QHttpHeaders hdrs = resp.headers();
            appendCorsHeaders(hdrs);
            resp.setHeaders(std::move(hdrs));
        });

    // 2. 注册每条业务路由，使用 QFuture 异步处理
    // route() 内部将 future 挂起，事件循环继续处理其他连接，实现真正并发
    // handler 通过 shared_ptr 共享，每条路由只拷贝一次，热路径零拷贝
    for (const auto& entry : router->routeList()) {
        auto handlerPtr = std::make_shared<const RouteHandler>(entry.handler);
        server_->route(entry.path, toQtMethod(entry.method), this,
            [handlerPtr](const QHttpServerRequest& req) -> QFuture<QHttpServerResponse> {
                // 在事件循环线程解析请求（QHttpServerRequest 不可跨线程访问）
                HttpRequest httpReq = parseHttpRequest(req);

                LOG_DEBUG(QString("[HttpServer] 处理请求: %1").arg(httpReq.path));

                // 派发到全局线程池执行业务逻辑，返回 future
                return QtConcurrent::run(
                    [httpReq = std::move(httpReq), handlerPtr]() {
                        auto httpResp = (*handlerPtr)(httpReq);

                        LOG_DEBUG(QString("[HttpServer] 请求完成: %1 -> %2")
                                      .arg(httpReq.path).arg(httpResp.statusCode));

                        auto status = static_cast<QHttpServerResponse::StatusCode>(
                            httpResp.statusCode);
                        return QHttpServerResponse(kJsonContentType,
                                                   httpResp.body.toUtf8(), status);
                    });
            });
    }

    // 3. OPTIONS 预检（同步，极快）+ 未匹配路径 404
    // setMissingHandler 处理所有 route() 未匹配的请求
    server_->setMissingHandler(this,
        [](const QHttpServerRequest& req, QHttpServerResponder& responder) {
            QHttpHeaders corsHeaders;
            appendCorsHeaders(corsHeaders);

            if (req.method() == QHttpServerRequest::Method::Options) {
                responder.write(corsHeaders, QHttpServerResponder::StatusCode::NoContent);
                return;
            }

            corsHeaders.append(QHttpHeaders::WellKnownHeader::ContentType, kJsonContentType);
            responder.write(k404Body, corsHeaders, QHttpServerResponder::StatusCode::NotFound);
        });
}

QHttpServer* HttpServer::server() const {
    return server_;
}

bool HttpServer::isListening() const {
    if (!running_ || !tcpServer_) {
        return false;
    }
    return tcpServer_->isListening();
}

}  // namespace api
}  // namespace wekey
