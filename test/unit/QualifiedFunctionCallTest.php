<?php

require_once __DIR__ . '/../../vendor/autoload.php';

use PhpParser\Node;
use PhpParser\Node\Expr\FuncCall;
use PhpParser\NodeTraverser;
use PhpParser\NodeVisitorAbstract;
use PhpParser\ParserFactory;

class QualifiedFunctionCallTest extends PHPUnit_Framework_TestCase
{
    protected $exclude = ['test', 'vendor'];

    /**
     * @dataProvider fileProvider
     */
    public function test($filename)
    {
        $traverser = new NodeTraverser();
        $traverser->addVisitor(new QualifiedNodeVisitor());

        $parser = (new ParserFactory())->create(ParserFactory::PREFER_PHP5);

        $stmts = $parser->parse(file_get_contents($filename));

        try {
            $traverser->traverse($stmts);
        }
        catch (\LogicException $e) {
            $function = $e->getMessage();
            $this->fail("$filename contains an unqulified use of $function().");
        }
    }

    public function fileProvider()
    {
        $root = dirname(dirname(__DIR__));
        $directory = new \RecursiveDirectoryIterator($root);
        $iterator = new \RecursiveIteratorIterator($directory);

        foreach ($this->exclude as $directory) {
            $iterator = new \CallbackFilterIterator($iterator, function ($current) use ($root, $directory) {
                return strpos($current, $root . '/' . $directory . '/') !== 0;
            });
        }

        $matches = new \RegexIterator($iterator, '/^.+\.php$/i', \RecursiveRegexIterator::GET_MATCH);

        $return = [];
        foreach ($matches as $filename) {
            $return[] = [$filename[0]];
        }

        return $return;
    }
}

class QualifiedNodeVisitor extends NodeVisitorAbstract
{
    public function leaveNode(Node $node) {
        if ($node instanceof FuncCall && $node->name->isUnqualified()) {
            throw new \LogicException($node->name->toString());
        }
    }
}
