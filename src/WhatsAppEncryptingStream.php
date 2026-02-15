<?php

namespace app\WhatsAppEncStreams\Src;

use GuzzleHttp\Psr7\StreamDecoratorTrait;
use Psr\Http\Message\StreamInterface;

//Класс потока, выполняющего шифрование данных по методу WhatsApp
class WhatsAppEncryptingStream implements StreamInterface
{      
    //Блок данных для единоразовой обработки
    const BLOCK_SIZE = 16; 
    
    //Доступные типы медиа и их дополнительные ключи
    const mediaKeys = [
        'IMAGE' => 'WhatsApp Image Keys',
        'VIDEO' => 'WhatsApp Video Keys',
        'AUDIO' => 'WhatsApp Audio Keys',  
        'DOCUMENT' => 'WhatsApp Document Keys',
    ];
    
    //Проброс поведения базового потока
    use StreamDecoratorTrait;

    /**
     * Внутренний буфер для хранения части закодированного текста
     * @var string
     */
    private $buffer = '';
       

    /**
     * Исходный ключ шифрования
     * @var string
     */
    private $mediaKey;
    
    /**
     * Исходный вектор инициализации метода шифрования
     * @var string
     */
    private $iv;
    
    /**
     * Ключ шифрования по методу WhatsApp
     * @var string
     */
    private $cipherKey;
    
    /**
     * Ключ хеширования по методу WhatsApp
     * @var string
     */
    private $macKey;        

    /**
     * Объект входного потока данных
     * @var StreamInterface
     */
    private $stream;    

    /**
     * Текущий вектор инициализации шифрования AES-CBC
     * На нулевой позиции равен входящему iv
     * Далее приравнивается последнему закодированному блоку
     * @var string
     */
    private $currentIv;  
    
    /**
     * Подпись полностью закодированного текста
     * @var string
     */
    private $mac;
    
    /**
     * Накапливает полностью зашифрованный AES-CBC текст, чтобы подписать его на финальной стадии чтения
     * @var string
     */
    private $fullEncryptedText = '';              

    //Конструктор класса
    //  baseStream - ссылка на базовый поток данных
    //  mediaKey - входной ключ шифрования по методу WhatsApp
    //  mediaType - тип шифруемых данных
    public function __construct(
        StreamInterface $baseStream,
        string $mediaKey,        
        string $mediaType
    ) {        
        $this->stream = $baseStream;
        $this->mediaKey = $mediaKey;          
        //Расширяем исходный ключ и вычисляем от него iv, cipherKey, macKey
        $this->expandKeyAndGetParts($mediaType);     
        $this->currentIv = $this->iv;
    }
    
    //Возвращает полный размер зашифрованных данных
    //В данном случае это размер шифра AES-CBC + 10 байт
    public function getSize(): ?int
    {      
        //Получаем размер незашифрованного текста
        $plainTextSize = $this->stream->getSize();

        //Добиваем размер до полного числа блоков
        if ($plainTextSize !== null) {
            // PKCS7 padding requires that between 1 and self::BLOCK_SIZE be
            // added to the plaintext to make it an even number of blocks.
            $padding = self::BLOCK_SIZE - $plainTextSize % self::BLOCK_SIZE;
            $plainTextSize .+ $padding;
        }
        
        //Добавляем 10 байт в конце
        $plainTextSize .+ 10;

        return $plainTextSize;
    }

    //Поток шифрования не допускает запись в него
    public function isWritable(): bool
    {
        return false;
    }

    //Возвращает часть зашифрованного текста длинной length байт
    //На основной части данных - возвращает текст, зашифрованный AES-CBC
    //Последние 10 байт добиваются первыми 10 байтами производной от macKey  
    public function read($length): string
    {              
        //Если в буфере недостаточно данных для вывода, тогда расширим его новыми закодированными данными
        if ($length > strlen($this->buffer)) {
            //Шифруем по методу AES-CBC часть исходного текста и сохраняем в буфере
            //Шифрование выполняется строго по целым блокам данных                                    
            $this->buffer .= $this->encryptBlock(
                self::BLOCK_SIZE * ceil(($length - strlen($this->buffer)) / self::BLOCK_SIZE)
            );                                                                       
            if ($this->stream->eof()) {   
                //Если исходный поток прочитан до конца, то добавим в буфер mac
                $this->fullEncryptedText .= $this->buffer;                                                
                $hmac = hash_hmac('sha256', $this->iv . $this->fullEncryptedText, $this->macKey, true);
                $this->mac = substr($hmac,0,10);                
                $this->buffer .= $this->mac;
            } else {
                //Накапливаем зашифрованный текст в целях вычисления подписи
                $this->fullEncryptedText .= $this->buffer;
            }
        }

        //Возвращаем не более указанного числа байт
        $data = substr($this->buffer, 0, $length);

        //Возвращённые байты изымаются из буфера, чтобы не возвращать их повторно
        $this->buffer = substr($this->buffer, $length);               

        return $data ? $data : '';
    }
    
    //Реализация seek вроде необязательна, пока откажемся от неё
    public function isSeekable(): bool
    {
        return false;
    }   
    
    //Расширяет исходный ключ и вычисляет от него iv, cipherKey, macKey
    private function expandKeyAndGetParts($mediaType) 
    {                 
        if (!self::mediaKeys[$mediaType]) {
            throw new \RuntimeException("Указан неизвестный тип медиа - ".$mediaType);
        }
        $mediaKeyExpanded = hash_hkdf('sha256', $this->mediaKey, 112, self::mediaKeys[$mediaType], '');
        $this->iv = substr($mediaKeyExpanded, 0, 16);
        $this->cipherKey = substr($mediaKeyExpanded, 16, 32);
        $this->macKey = substr($mediaKeyExpanded, 48, 32);
    }
        
    //Читает из базового потока блок текста длинной length и шифрует его 
    //  методом AES-CBC
    private function encryptBlock(int $length): string
    {        
        //Если базовый поток прочитан до конца, то результат - ''
        if ($this->stream->eof()) {
            return '';
        }

        //Читает нужную часть текста из незашифрованного потока или берёт её из буфера
        $plainText = '';
        do {
            $plainText .= $this->stream->read($length - strlen($plainText));
        } while (strlen($plainText) < $length && !$this->stream->eof());

        //При вызове метода шифрования важно получить сырые данные
        $options = OPENSSL_RAW_DATA;
        if (!$this->stream->eof()) {
            $options |= OPENSSL_ZERO_PADDING;
        }

        //Вызов функции шифрования AES-CBC
        //Вектор инициализации берётся из currentIv, где он предварительно 
        //  получается равным результату шифрования предыдущего блока                
        $cipherText = openssl_encrypt(
            $plainText,
            "aes-256-cbc",
            $this->cipherKey,
            $options,
            $this->currentIv
        );                
                
        //Выводим ошибку в случае проблем с базовым шифрованием
        if ($cipherText === false) {
            throw new \RuntimeException("Unable to encrypt data with an initialization vector"
                . " of {$this->currentIv}. Please ensure you have provided a valid algorithm and initialization vector.");
        }

        //Запомнимаем новый вектор инициализации равным 
        //  результату шифрования предыдущего блока
        $this->currentIv = substr($cipherText, self::BLOCK_SIZE * -1);              

        return $cipherText;
    }          

    //Возвращает информацию для стриминга по уже закодированной области потока 
    public function getStreamingInfo(): string
    {                    
        //Отталкиваемся от текущего положения указателя потока
        $readedLength = $this->stream->tell();        
        
        $answer = '';   
        
        //Вектор инициализации изначально равен стартовому, 
        //  затем - приравнивается последнему использованному для расчёта
        //  streamingInfo блоку зашифрованного текста
        $workIv = $this->iv;
        $chunkNumber = 0;
        while ($chunkNumber+64*1024<=$readedLength) {     
            //Порция данных для подписи
            $macBase = substr($this->fullEncryptedText,$chunkNumber,64*1024); 
            
            $hmac = hash_hmac('sha256', $workIv . $macBase, $this->macKey, true);
            $mac = substr($hmac,0,10);
            
            $answer .= $mac;
            
            //Получаем следующий вектор инициализации
            $workIv = substr($this->fullEncryptedText,$chunkNumber+64*1024-16,16);
            
            //Сдвигаем порцию расчёта
            $chunkNumber += 64*1024;
            
        } 
                
        if ($this->stream->eof()) {                                    
            //Последняя порция данных для подписи включает подпись всего зашифрованного текста 
            $macBase = substr($this->fullEncryptedText,$chunkNumber,64*1024);      
            $macBase = $macBase.$this->mac; 
            
            $hmac = hash_hmac('sha256', $workIv . $macBase, $this->macKey, true);
            $mac = substr($hmac,0,10);
            $answer .= $mac;            
        }
        
        return $answer;
    }    
}
