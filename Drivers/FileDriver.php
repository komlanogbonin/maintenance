<?php

namespace Lexik\Bundle\MaintenanceBundle\Drivers;

/**
 * Class FileDriver
 * @package Lexik\Bundle\MaintenanceBundle\Drivers
 */
class FileDriver extends AbstractDriver implements DriverTtlInterface
{
    /**
     * @var mixed
     */
    protected $filePath;

    /**
     * @var array
     */
    protected $routes;

    /**
     * Constructor
     *
     * @param array $options    Options driver
     */
    public function __construct(array $options = array())
    {
        parent::__construct($options);

        if ( ! isset($options['file_path'])) {
            throw new \InvalidArgumentException('$options[\'file_path\'] cannot be defined if Driver File configuration is used');
        }
        if (null !== $options) {
            $this->filePath = $options['file_path'];
        }

        $this->routes = [];
        $this->options = $options;
    }

    /**
     * {@inheritDoc}
     */
    protected function createLock()
    {
        return (bool)file_put_contents($this->filePath,json_encode([
            'routes'=>$this->getRoutes(),
            'ttl'=>$this->getTtl()
        ]));
    }

    /**
     * {@inheritDoc}
     */
    protected function createUnlock()
    {
        return @unlink($this->filePath);
    }

    /**
     * {@inheritDoc}
     *
     * @return bool
     * @throws \Exception
     */
    public function isExists()
    {
        if (file_exists($this->filePath)) {
            if (isset($this->options['ttl']) && is_numeric($this->options['ttl'])) {
                return $this->isEndTime($this->options['ttl']);
            }
            return true;
        } else {
            return false;
        }
    }

    /**
     * Test if time to life is expired
     *
     * @param integer $timeTtl The ttl value
     * @return bool
     * @throws \Exception
     */
    public function isEndTime($timeTtl)
    {
        $now = new \DateTime('now');
        $accessTime = date("Y-m-d H:i:s.", filemtime($this->filePath));
        $accessTime = new \DateTime($accessTime);
        $accessTime->modify(sprintf('+%s seconds', $timeTtl));

        if ($accessTime < $now) {
            return $this->createUnlock();
        } else {
            return true;
        }
    }

    /**
     * {@inheritDoc}
     */
    public function getMessageLock($resultTest)
    {
        $key = $resultTest ? 'lexik_maintenance.success_lock_file' : 'lexik_maintenance.not_success_lock';

        return $this->translator->trans($key, array(), 'maintenance');
    }

    /**
     * {@inheritDoc}
     */
    public function getMessageUnlock($resultTest)
    {
        $key = $resultTest ? 'lexik_maintenance.success_unlock' : 'lexik_maintenance.not_success_unlock';

        return $this->translator->trans($key, array(), 'maintenance');
    }

    public function setTtl($value)
    {
        $this->options['ttl'] = $value;
    }

    public function getTtl()
    {
        return $this->options['ttl'];
    }

    public function hasTtl()
    {
        return array_key_exists('ttl', $this->options);
    }

    public function setRoutes(array $routes)
    {
        $this->routes = $routes;
    }

    /**
     * @return array
     */
    public function getRoutes()
    {
        return $this->routes;
    }

}
