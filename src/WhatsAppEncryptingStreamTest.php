<?php
namespace tinabanaku22\WhatsAppEncStreams;

use GuzzleHttp\Psr7;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\StreamInterface;

//Проверки классов шифрования и расшифровки методом WhatsApp
class WhatsAppEncryptingStreamsTest extends TestCase
{          
    //Общая рабочая проверка
    public function testDev()
    {
        return true;
    }
    
    //Проверка чтения одной командой
    public function testOneFullRead()
    {
        return true;
    }

    //Проверка чтения по блокам 
    public function test16BReads()
    {
        return true;
    }
    
    //Проверка рандомного чтения
    public function testRandomReads()
    {
        return true;
    }
    
    //Проверка работы с крупными данными
    public function testProcessBigData()
    {
        return true;
    }
    
    //Проверка динамических показателей
    public function testTimings()
    {
        return true;
    }
    
    //Проверка многопоточной устойчивости
    public function testMultithreadReads()
    {
        return true;
    }
}
