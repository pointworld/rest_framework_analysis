"""
Provides an APIView class that is the base of all views in REST framework.
"""
from __future__ import unicode_literals

from django.conf import settings
from django.core.exceptions import PermissionDenied
from django.db import connection, models, transaction
from django.http import Http404
from django.http.response import HttpResponseBase
from django.utils.cache import cc_delim_re, patch_vary_headers
from django.utils.encoding import smart_text
from django.views.decorators.csrf import csrf_exempt
from django.views.generic import View

from rest_framework import exceptions, status
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.schemas import DefaultSchema
from rest_framework.settings import api_settings
from rest_framework.utils import formatting


def get_view_name(view):
    """
    Given a view instance, return a textual name to represent the view.
    This name is used in the browsable API, and in OPTIONS responses.

    This function is the default for the `VIEW_NAME_FUNCTION` setting.
    """
    # Name may be set by some Views, such as a ViewSet.
    name = getattr(view, 'name', None)
    if name is not None:
        return name

    name = view.__class__.__name__
    name = formatting.remove_trailing_string(name, 'View')
    name = formatting.remove_trailing_string(name, 'ViewSet')
    name = formatting.camelcase_to_spaces(name)

    # Suffix may be set by some Views, such as a ViewSet.
    suffix = getattr(view, 'suffix', None)
    if suffix:
        name += ' ' + suffix

    return name


def get_view_description(view, html=False):
    """
    Given a view instance, return a textual description to represent the view.
    This name is used in the browsable API, and in OPTIONS responses.

    This function is the default for the `VIEW_DESCRIPTION_FUNCTION` setting.
    """
    # Description may be set by some Views, such as a ViewSet.
    description = getattr(view, 'description', None)
    if description is None:
        description = view.__class__.__doc__ or ''

    description = formatting.dedent(smart_text(description))
    if html:
        return formatting.markup_description(description)
    return description


def set_rollback():
    atomic_requests = connection.settings_dict.get('ATOMIC_REQUESTS', False)
    if atomic_requests and connection.in_atomic_block:
        transaction.set_rollback(True)


def exception_handler(exc, context):
    """
    Returns the response that should be used for any given exception.

    By default we handle the REST framework `APIException`, and also
    Django's built-in `Http404` and `PermissionDenied` exceptions.

    Any unhandled exceptions may return `None`, which will cause a 500 error
    to be raised.
    """
    if isinstance(exc, Http404):
        exc = exceptions.NotFound()
    elif isinstance(exc, PermissionDenied):
        exc = exceptions.PermissionDenied()

    if isinstance(exc, exceptions.APIException):
        headers = {}
        if getattr(exc, 'auth_header', None):
            headers['WWW-Authenticate'] = exc.auth_header
        if getattr(exc, 'wait', None):
            headers['Retry-After'] = '%d' % exc.wait

        if isinstance(exc.detail, (list, dict)):
            data = exc.detail
        else:
            data = {'detail': exc.detail}

        set_rollback()
        return Response(data, status=exc.status_code, headers=headers)

    return None


class APIView(View):

    # The following policies may be set at either globally, or per-view.
    renderer_classes = api_settings.DEFAULT_RENDERER_CLASSES
    parser_classes = api_settings.DEFAULT_PARSER_CLASSES
    authentication_classes = api_settings.DEFAULT_AUTHENTICATION_CLASSES
    throttle_classes = api_settings.DEFAULT_THROTTLE_CLASSES
    permission_classes = api_settings.DEFAULT_PERMISSION_CLASSES
    content_negotiation_class = api_settings.DEFAULT_CONTENT_NEGOTIATION_CLASS
    metadata_class = api_settings.DEFAULT_METADATA_CLASS
    versioning_class = api_settings.DEFAULT_VERSIONING_CLASS

    # Allow dependency injection of other settings to make testing easier.
    settings = api_settings

    schema = DefaultSchema()

    @classmethod
    def as_view(cls, **initkwargs):
        """
        Store the original class on the view function.

        This allows us to discover information about the view when we do URL
        reverse lookups.  Used for breadcrumb generation.
        """
        if isinstance(getattr(cls, 'queryset', None), models.query.QuerySet):
            def force_evaluation():
                raise RuntimeError(
                    'Do not evaluate the `.queryset` attribute directly, '
                    'as the result will be cached and reused between requests. '
                    'Use `.all()` or call `.get_queryset()` instead.'
                )
            cls.queryset._fetch_all = force_evaluation

        view = super(APIView, cls).as_view(**initkwargs)
        view.cls = cls
        view.initkwargs = initkwargs

        # Note: session based authentication is explicitly CSRF validated,
        # all other authentication is CSRF exempt.
        return csrf_exempt(view)

    @property
    def allowed_methods(self):
        """
        Wrap Django's private `_allowed_methods` interface in a public property.
        """
        return self._allowed_methods()

    @property
    def default_response_headers(self):
        headers = {
            'Allow': ', '.join(self.allowed_methods),
        }
        if len(self.renderer_classes) > 1:
            headers['Vary'] = 'Accept'
        return headers

    def http_method_not_allowed(self, request, *args, **kwargs):
        """
        If `request.method` does not correspond to a handler method,
        determine what kind of exception to raise.
        """
        raise exceptions.MethodNotAllowed(request.method)

    def permission_denied(self, request, message=None):
        """
        If request is not permitted, determine what kind of exception to raise.
        ## 如果请求不被允许，则抛出对应类型的异常
        """
        if request.authenticators and not request.successful_authenticator:
            ## 抛出未认证异常
            raise exceptions.NotAuthenticated()
        ## 抛出权限拒绝异常
        raise exceptions.PermissionDenied(detail=message)

    def throttled(self, request, wait):
        """
        If request is throttled, determine what kind of exception to raise.
        """
        raise exceptions.Throttled(wait)

    def get_authenticate_header(self, request):
        """
        If a request is unauthenticated, determine the WWW-Authenticate
        header to use for 401 responses, if any.
        """
        authenticators = self.get_authenticators()
        if authenticators:
            return authenticators[0].authenticate_header(request)

    def get_parser_context(self, http_request):
        """
        Returns a dict that is passed through to Parser.parse(),
        as the `parser_context` keyword argument.
        """
        # Note: Additionally `request` and `encoding` will also be added
        #       to the context by the Request object.
        return {
            'view': self,
            'args': getattr(self, 'args', ()),
            'kwargs': getattr(self, 'kwargs', {})
        }

    def get_renderer_context(self):
        """
        Returns a dict that is passed through to Renderer.render(),
        as the `renderer_context` keyword argument.
        """
        # Note: Additionally 'response' will also be added to the context,
        #       by the Response object.
        return {
            'view': self,
            'args': getattr(self, 'args', ()),
            'kwargs': getattr(self, 'kwargs', {}),
            'request': getattr(self, 'request', None)
        }

    def get_exception_handler_context(self):
        """
        Returns a dict that is passed through to EXCEPTION_HANDLER,
        as the `context` argument.
        """
        return {
            'view': self,
            'args': getattr(self, 'args', ()),
            'kwargs': getattr(self, 'kwargs', {}),
            'request': getattr(self, 'request', None)
        }

    def get_view_name(self):
        """
        Return the view name, as used in OPTIONS responses and in the
        browsable API.
        """
        func = self.settings.VIEW_NAME_FUNCTION
        return func(self)

    def get_view_description(self, html=False):
        """
        Return some descriptive text for the view, as used in OPTIONS responses
        and in the browsable API.
        """
        func = self.settings.VIEW_DESCRIPTION_FUNCTION
        return func(self, html)

    # API policy instantiation methods

    def get_format_suffix(self, **kwargs):
        """
        Determine if the request includes a '.json' style format suffix
        """
        if self.settings.FORMAT_SUFFIX_KWARG:
            return kwargs.get(self.settings.FORMAT_SUFFIX_KWARG)

    def get_renderers(self):
        """
        Instantiates and returns the list of renderers that this view can use.
        """
        return [renderer() for renderer in self.renderer_classes]

    def get_parsers(self):
        """
        Instantiates and returns the list of parsers that this view can use.
        ## 返回该视图所支持的解析器类的实例的列表
        """
        return [parser() for parser in self.parser_classes]

    def get_authenticators(self):
        """
        Instantiates and returns the list of authenticators that this view can use.
        ## 返回由该视图支持的认证类的实例所组成的列表
        """
        return [auth() for auth in self.authentication_classes]

    def get_permissions(self):
        """
        Instantiates and returns the list of permissions that this view requires.
        ## 遍历该视图所存在的权限类列表，返回实例化后的权限类列表
        """
        return [permission() for permission in self.permission_classes]

    def get_throttles(self):
        """
        Instantiates and returns the list of throttles that this view uses.
        """
        return [throttle() for throttle in self.throttle_classes]

    def get_content_negotiator(self):
        """
        Instantiate and return the content negotiation class to use.
        ## 返回需要使用的内容协商类的实例
        """
        if not getattr(self, '_negotiator', None):
            self._negotiator = self.content_negotiation_class()
        return self._negotiator

    def get_exception_handler(self):
        """
        Returns the exception handler that this view uses.
        """
        return self.settings.EXCEPTION_HANDLER

    # API policy implementation methods

    def perform_content_negotiation(self, request, force=False):
        """
        Determine which renderer and media type to use render the response.
        """
        renderers = self.get_renderers()
        conneg = self.get_content_negotiator()

        try:
            return conneg.select_renderer(request, renderers, self.format_kwarg)
        except Exception:
            if force:
                return (renderers[0], renderers[0].media_type)
            raise

    def perform_authentication(self, request):
        """
        Perform authentication on the incoming request.

        Note that if you override this and simply 'pass', then authentication
        will instead be performed lazily, the first time either
        `request.user` or `request.auth` is accessed.
        """
        request.user

    def check_permissions(self, request):
        """
        Check if the request should be permitted.
        Raises an appropriate exception if the request is not permitted.
        ## 检查请求是否应该被允许
        ## 如果请求不被允许，则抛出一个适当的错误
        """
        ## 遍历权限类的实例列表
        for permission in self.get_permissions():
            if not permission.has_permission(request, self):
                self.permission_denied(
                    request, message=getattr(permission, 'message', None)
                )

    def check_object_permissions(self, request, obj):
        """
        Check if the request should be permitted for a given object.
        Raises an appropriate exception if the request is not permitted.
        """
        for permission in self.get_permissions():
            if not permission.has_object_permission(request, self, obj):
                self.permission_denied(
                    request, message=getattr(permission, 'message', None)
                )

    def check_throttles(self, request):
        """
        Check if request should be throttled.
        Raises an appropriate exception if the request is throttled.
        """
        for throttle in self.get_throttles():
            if not throttle.allow_request(request, self):
                self.throttled(request, throttle.wait())

    def determine_version(self, request, *args, **kwargs):
        """
        If versioning is being used, then determine any API version for the
        incoming request. Returns a two-tuple of (version, versioning_scheme)
        """
        if self.versioning_class is None:
            return (None, None)
        scheme = self.versioning_class()
        return (scheme.determine_version(request, *args, **kwargs), scheme)

    # Dispatch methods

    def initialize_request(self, request, *args, **kwargs):
        """
        Returns the initial request object.
        ## 返回初始化的 request 对象
        """
        parser_context = self.get_parser_context(request)

        return Request(
            ## 原始 request 对象
            request,
            ## 解析器
            parsers=self.get_parsers(),
            ## 认证器
            authenticators=self.get_authenticators(),
            ## 内容协商
            negotiator=self.get_content_negotiator(),
            ## 解析器上下文
            parser_context=parser_context
        )

    def initial(self, request, *args, **kwargs):
        """
        Runs anything that needs to occur prior to calling the method handler.
        ## 在调用方法处理器之前，进行任何需要的动作
        ## 如执行权限认证和限制、内容协商等
        ## 通常我们不需要重写此方法
        """
        self.format_kwarg = self.get_format_suffix(**kwargs)

        # Perform content negotiation and store the accepted info on the request
        ## 执行内容协商和存储一些可被接受的信息到 request 中
        neg = self.perform_content_negotiation(request)
        ## 设置请求可接受的渲染器和媒体类型
        request.accepted_renderer, request.accepted_media_type = neg

        # Determine the API version, if versioning is in use.
        ## 根据请求确定 API 版本
        version, scheme = self.determine_version(request, *args, **kwargs)
        ## 设置请求的版本和版本协议
        request.version, request.versioning_scheme = version, scheme

        # Ensure that the incoming request is permitted
        ## 确保进来的请求是被允许的

        ## 执行认证
        self.perform_authentication(request)
        ## 检查权限（控制访问权限）
        self.check_permissions(request)
        ## 检查节流（控制访问频率）
        self.check_throttles(request)

    def finalize_response(self, request, response, *args, **kwargs):
        """
        Returns the final response object.
        ## 返回最终的响应对象
        """
        # Make the error obvious if a proper response is not returned
        assert isinstance(response, HttpResponseBase), (
            'Expected a `Response`, `HttpResponse` or `HttpStreamingResponse` '
            'to be returned from the view, but received a `%s`'
            % type(response)
        )

        if isinstance(response, Response):
            if not getattr(request, 'accepted_renderer', None):
                neg = self.perform_content_negotiation(request, force=True)
                request.accepted_renderer, request.accepted_media_type = neg

            ## 设置可被接收的渲染器
            response.accepted_renderer = request.accepted_renderer
            ## 设置可被接收的媒体文件类型
            response.accepted_media_type = request.accepted_media_type
            ## 设置渲染上下文
            response.renderer_context = self.get_renderer_context()

        # Add new vary headers to the response instead of overwriting.
        vary_headers = self.headers.pop('Vary', None)
        if vary_headers is not None:
            patch_vary_headers(response, cc_delim_re.split(vary_headers))

        for key, value in self.headers.items():
            response[key] = value

        return response

    def handle_exception(self, exc):
        """
        Handle any exception that occurs, by returning an appropriate response,
        or re-raising the error.
        ## 任何被处理请求的方法抛出的异常都会被传递给该方法进行处理
        ## 该方法既不返回 Response 的实例，也不重新抛出异常
        ##
        ## 默认的实现会处理 rest_framework.exceptions.APIException 的任何子类异常，
        ## 以及 Django 的 Http404 和 PermissionDenies 异常，并且返回一个适当的错误响应
        ##
        ## 如果你需要在自己的 API 中自定义返回的错误响应，你需要重写该方法
        """
        if isinstance(exc, (exceptions.NotAuthenticated,
                            exceptions.AuthenticationFailed)):
            # WWW-Authenticate header for 401 responses, else coerce to 403
            auth_header = self.get_authenticate_header(self.request)

            if auth_header:
                exc.auth_header = auth_header
            else:
                exc.status_code = status.HTTP_403_FORBIDDEN

        exception_handler = self.get_exception_handler()

        context = self.get_exception_handler_context()
        response = exception_handler(exc, context)

        if response is None:
            self.raise_uncaught_exception(exc)

        response.exception = True
        return response

    def raise_uncaught_exception(self, exc):
        if settings.DEBUG:
            request = self.request
            renderer_format = getattr(request.accepted_renderer, 'format')
            use_plaintext_traceback = renderer_format not in ('html', 'api', 'admin')
            request.force_plaintext_errors(use_plaintext_traceback)
        raise exc

    # Note: Views are made CSRF exempt from within `as_view` as to prevent
    # accidental removal of this exemption in cases where `dispatch` needs to
    # be overridden.
    def dispatch(self, request, *args, **kwargs):
        """
        `.dispatch()` is pretty much the same as Django's regular dispatch,
        but with extra hooks for startup, finalize, and exception handling.
        """
        self.args = args
        self.kwargs = kwargs
        ## 封装请求对象（添加解析器、认证器、内容协商、解析器上下文）
        request = self.initialize_request(request, *args, **kwargs)
        self.request = request
        self.headers = self.default_response_headers  # deprecate?

        try:
            ## 在执行方法处理器之前进行一些需要的动作（内容协商、认证、权限、节流等）
            self.initial(request, *args, **kwargs)

            # Get the appropriate handler method
            ## 通过反射获取相应的处理器方法
            if request.method.lower() in self.http_method_names:
                handler = getattr(self, request.method.lower(),
                                  self.http_method_not_allowed)
            else:
                handler = self.http_method_not_allowed

            ## 执行处理器方法，得到响应对象
            response = handler(request, *args, **kwargs)

        except Exception as exc:
            ## 任何被处理请求的方法抛出的异常都会被传递给该方法进行处理
            response = self.handle_exception(exc)

        ## 封装最终的响应对象
        self.response = self.finalize_response(request, response, *args, **kwargs)
        ## 返回响应对象
        return self.response

    def options(self, request, *args, **kwargs):
        """
        Handler method for HTTP 'OPTIONS' request.
        """
        if self.metadata_class is None:
            return self.http_method_not_allowed(request, *args, **kwargs)
        data = self.metadata_class().determine_metadata(request, self)
        return Response(data, status=status.HTTP_200_OK)
