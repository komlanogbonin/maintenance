<?php

namespace Lexik\Bundle\MaintenanceBundle\Listener;

use ErrorException;
use Lexik\Bundle\MaintenanceBundle\Drivers\DriverFactory;
use Lexik\Bundle\MaintenanceBundle\Exception\ServiceUnavailableException;
use Symfony\Component\HttpFoundation\IpUtils;
use Symfony\Component\HttpKernel\Event\ResponseEvent as FilterResponseEvent;
use Symfony\Component\HttpKernel\Event\RequestEvent as GetResponseEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\UsageTrackingTokenStorage as TokenStorage;
/**
 * Listener to decide if user can access to the site
 *
 * @package LexikMaintenanceBundle
 * @author  Gilles Gauthier <g.gauthier@lexik.fr>
 */
class MaintenanceListener
{
    /**
     * Service driver factory
     *
     * @var DriverFactory
     */
    protected $driverFactory;

    /**
     * Authorized data
     *
     * @var array
     */
    protected $authorizedIps;

    /**
     * @var null|String
     */
    protected $path;
    /**
     * @var String
     */
    protected $role;

    /**
     * @var null|String
     */
    protected $host;

    /**
     * @var array|null
     */
    protected $ips;

    /**
     * @var array
     */
    protected $query;

    /**
     * @var array
     */
    protected $cookie;

    /**
     * @var null|String
     */
    protected $route;

    /**
     * @var array
     */
    protected $attributes;

    /**
     * @var Int|null
     */
    protected $http_code;

    /**
     * @var null|String
     */
    protected $http_status;

    /**
     * @var null|String
     */
    protected $http_exception_message;

    /**
     * @var bool
     */
    protected $handleResponse = false;

    /**
     * @var bool
     */
    protected $debug;

    /**
     * @var TokenStorage
     */
    protected $tokenStorage;

    /**
     * Constructor Listener
     *
     * Accepts a driver factory, and several arguments to be compared against the
     * incoming request.
     * When the maintenance mode is enabled, the request will be allowed to bypass
     * it if at least one of the provided arguments is not empty and matches the
     *  incoming request.
     *
     * @param DriverFactory $driverFactory The driver factory
     * @param TokenStorage $tokenStorage token storage to check user role
     * @param null $role maintenance must have role
     * @param null $path A regex for the path
     * @param null $host A regex for the host
     * @param null $ips The list of IP addresses
     * @param array $query Query arguments
     * @param array $cookie Cookies
     * @param null $route Route name
     * @param array $attributes Attributes
     * @param null $http_code http status code for response
     * @param null $http_status http status message for response
     * @param null $http_exception_message http response page exception message
     * @param bool $debug
     */
    public function __construct(
        DriverFactory $driverFactory,
        TokenStorage $tokenStorage,
        $role = null,
        $path = null,
        $host = null,
        $ips = null,
        $query = array(),
        $cookie = array(),
        $route = null,
        $attributes = array(),
        $http_code = null,
        $http_status = null,
        $http_exception_message = null,
        $debug = false
    )
    {
        $this->driverFactory = $driverFactory;
        $this->role = $role;
        $this->path = $path;
        $this->host = $host;
        $this->ips = $ips;
        $this->query = $query;
        $this->cookie = $cookie;
        $this->route = $route;
        $this->attributes = $attributes;
        $this->http_code = $http_code;
        $this->http_status = $http_status;
        $this->http_exception_message = $http_exception_message;
        $this->debug = $debug;
        $this->tokenStorage = $tokenStorage;
    }

    /**
     * @param GetResponseEvent $event GetResponseEvent
     *
     * @return void
     *
     * @throws ServiceUnavailableException|ErrorException
     */
    public function onKernelRequest(GetResponseEvent $event)
    {
        if (!$event->isMasterRequest()) {
            return;
        }

        $request = $event->getRequest();

        if (is_array($this->query)) {
            foreach ($this->query as $key => $pattern) {
                if (!empty($pattern) && preg_match('{' . $pattern . '}', $request->get($key))) {
                    return;
                }
            }
        }

        if (is_array($this->cookie)) {
            foreach ($this->cookie as $key => $pattern) {
                if (!empty($pattern) && preg_match('{' . $pattern . '}', $request->cookies->get($key))) {
                    return;
                }
            }
        }

        if (is_array($this->attributes)) {
            foreach ($this->attributes as $key => $pattern) {
                if (!empty($pattern) && preg_match('{' . $pattern . '}', $request->attributes->get($key))) {
                    return;
                }
            }
        }

        if (null !== $this->path && !empty($this->path) && preg_match('{' . $this->path . '}', rawurldecode($request->getPathInfo()))) {
            return;
        }
        if (null !== $this->host && !empty($this->host) && preg_match('{' . $this->host . '}i', $request->getHost())) {
            return;
        }

        if (count((array)$this->ips) !== 0 && $this->checkIps($request->getClientIp(), $this->ips)) {
            return;
        }

        $route = $request->get('_route');
        if ($this->isAllowedRoute($route)) {
            return;
        }
        if ($this->tokenStorage && $this->tokenStorage->getToken() && $this->tokenStorage->getToken()->getUser()) {
            if ($this->hasExpectedRole()) {
                return;
            }
        }

        // Get driver class defined in your configuration
        $driver = $this->driverFactory->getDriver();

        if ($driver->decide() && HttpKernelInterface::MASTER_REQUEST === $event->getRequestType()) {
            $this->handleResponse = true;
            throw new ServiceUnavailableException($this->http_exception_message);
        }
    }

    /**
     * Checks if the requested ip is valid.
     *
     * @param string $requestedIp
     * @param string|array $ips
     * @return boolean
     */
    protected function checkIps(string $requestedIp, $ips)
    {
        $ips = (array)$ips;

        $valid = false;
        $i = 0;

        while ($i < count($ips) && !$valid) {
            $valid = IpUtils::checkIp($requestedIp, $ips[$i]);
            $i++;
        }

        return $valid;
    }

    /**
     * @param $route
     * @return bool
     */
    private function isAllowedRoute($route)
    {
        $routes = array();

        if (!is_array($this->route)) {
            array_push($routes, $this->route);
        }

        foreach ($routes as $r) {
            if (null !== $this->route && preg_match('{' . $this->route . '}', $r) || (true === $this->debug && '_' === $route[0])) {
                return true;
            }
        }
        return false;
    }

    private function hasExpectedRole()
    {
        $roles = $this->tokenStorage->getToken()->getRoleNames();

        foreach ($roles as $role) {
            if ($this->role === $role) {
                return true;
            }
        }

        return false;
    }

    /**
     * Rewrites the http code of the response
     *
     * @param FilterResponseEvent $event FilterResponseEvent
     * @return void
     */
    public function onKernelResponse(FilterResponseEvent $event)
    {
        if ($this->handleResponse && $this->http_code !== null) {
            $response = $event->getResponse();
            $response->setStatusCode($this->http_code, $this->http_status);
        }
    }
}
