<?php

namespace Lexik\Bundle\MaintenanceBundle\Command;

use ErrorException;
use Lexik\Bundle\MaintenanceBundle\Drivers\AbstractDriver;
use Lexik\Bundle\MaintenanceBundle\Drivers\DriverFactory;
use Lexik\Bundle\MaintenanceBundle\Drivers\DriverTtlInterface;

use Lexik\Bundle\MaintenanceBundle\Drivers\FileDriver;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Command\Command;

/**
 * Create a lock action
 *
 * @package LexikMaintenanceBundle
 * @author  Gilles Gauthier <g.gauthier@lexik.fr>
 */
class DriverLockCommand extends Command
{
    protected $ttl;
    protected static $defaultName = 'kml:maintenance:lock';

    const OPTION_ROUTES = 'routes';

    /**
     * @var DriverFactory
     */
    private $factory;

    public function __construct(DriverFactory $factory)
    {
        $this->factory = $factory;
        parent::__construct(self::$defaultName);
    }

    /**
     * {@inheritdoc}
     */
    protected function configure()
    {
        $this
            ->setName(self::$defaultName)
            ->setDescription('Lock access to the site while maintenance...')
            ->addArgument('ttl', InputArgument::OPTIONAL, 'Overwrite time to life from your configuration, doesn\'t work with file or shm driver. Time in seconds.', null)
            ->addOption('routes', 'r', InputOption::VALUE_REQUIRED|InputOption::VALUE_IS_ARRAY, 'Allowed roles',[])
            ->addOption('routes-format', 'rf', InputOption::VALUE_OPTIONAL, 'Allowed roles',null)
            ->setHelp(<<<EOT

    You can optionally set a time to life of the maintenance

   <info>%command.full_name% 3600</info>

    You can execute the lock without a warning message which you need to interact with:

    <info>%command.full_name% --no-interaction</info>

    Or

    <info>%command.full_name% 3600 -n</info>
EOT
            );
    }

    /**
     * {@inheritdoc}
     * @throws ErrorException
     */
    protected function execute(InputInterface $input, OutputInterface $output)
    {
        $driver = $this->getDriver();

        if ($input->isInteractive()) {
            if (!$this->askConfirmation('WARNING! Are you sure you wish to continue? (y/n)', $input, $output)) {
                $output->writeln('<error>Maintenance cancelled!</error>');
                return;
            }
        } elseif (null !== $input->getArgument('ttl')) {
            $this->ttl = $input->getArgument('ttl');
        } elseif ($driver instanceof DriverTtlInterface) {
            $this->ttl = $driver->getTtl();
        }

        // set ttl from command line if given and driver supports it
        if ($driver instanceof FileDriver) {
            $driver->setTtl($this->ttl);
            $driver->setRoutes($input->getOption(self::OPTION_ROUTES));
        }

        $output->writeln(sprintf('<info>%s</info>',$driver->getMessageLock($driver->lock())));
    }

    /**
     * {@inheritdoc}
     * @throws ErrorException
     */
    protected function interact(InputInterface $input, OutputInterface $output)
    {
        $driver = $this->getDriver();
        $default = $driver->getOptions();

        $formatter = $this->getHelperSet()->get('formatter');

        if (null !== $input->getArgument('ttl') && !is_numeric($input->getArgument('ttl'))) {
            throw new \InvalidArgumentException('Time must be an integer');
        }

        $output->writeln(array(
            '',
            $formatter->formatBlock('You are about to launch maintenance', 'bg=red;fg=white', true),
            '',
        ));

        $ttl = null;
        if ($driver instanceof DriverTtlInterface) {
            if (null === $input->getArgument('ttl')) {
                $output->writeln(array(
                    '',
                    'Do you want to redefine maintenance life time ?',
                    'If yes enter the number of seconds. Press enter to continue',
                    '',
                ));

                $ttl = $this->askAndValidate(
                    $input,
                    $output,
                    sprintf('<info>%s</info> [<comment>Default value in your configuration: %s</comment>]%s ', 'Set time', $driver->hasTtl() ? $driver->getTtl() : 'unlimited', ':'),
                    function($value) use ($default) {
                        if (!is_numeric($value) && null === $default) {
                            return null;
                        } elseif (!is_numeric($value)) {
                            throw new \InvalidArgumentException('Time must be an integer');
                        }
                        return $value;
                    },
                    1,
                    isset($default['ttl']) ? $default['ttl'] : 0
                );
            }

            $ttl = (int) $ttl;
            $this->ttl = $ttl ? $ttl : $input->getArgument('ttl');
        } else {
            $output->writeln(array(
                '',
                sprintf('<fg=red>Ttl doesn\'t work with %s driver</>', get_class($driver)),
                '',
            ));
        }
    }

    /**
     * Get driver
     *
     * @return AbstractDriver
     * @throws ErrorException
     */
    private function getDriver()
    {
        return $this->factory->getDriver();
    }

    /**
     * This method ensure that we stay compatible with symfony console 2.3 by using the deprecated dialog helper
     * but use the ConfirmationQuestion when available.
     *
     * @param $question
     * @param InputInterface $input
     * @param OutputInterface $output
     * @return mixed
     */
    protected function askConfirmation($question, InputInterface $input, OutputInterface $output) {
        if (!$this->getHelperSet()->has('question')) {
            return $this->getHelper('dialog')
                ->askConfirmation($output, '<question>' . $question . '</question>', 'y');
        }

        return $this->getHelper('question')
            ->ask($input, $output, new \Symfony\Component\Console\Question\ConfirmationQuestion($question));
    }

    /**
     * This method ensure that we stay compatible with symfony console 2.3 by using the deprecated dialog helper
     * but use the ConfirmationQuestion when available.
     *
     * @param InputInterface $input
     * @param OutputInterface $output
     * @param $question
     * @param $validator
     * @param int $attempts
     * @param null $default
     * @return mixed
     */
    protected function askAndValidate(InputInterface $input, OutputInterface $output, $question, $validator, $attempts = 1, $default = null) {
        if (!$this->getHelperSet()->has('question')) {
            return $this->getHelper('dialog')
                ->askAndValidate($output, $question, $validator, $attempts, $default);
        }

        $question = new \Symfony\Component\Console\Question\Question($question, $default);
        $question->setValidator($validator);
        $question->setMaxAttempts($attempts);

        return $this->getHelper('question')
            ->ask($input, $output, $question);
    }
}
