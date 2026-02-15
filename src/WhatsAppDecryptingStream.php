<?php

namespace app\WhatsAppEncStreams\Src;

use GuzzleHttp\Psr7\StreamDecoratorTrait;
use Psr\Http\Message\StreamInterface;

//Класс потока, выполняющего расшифровку данных по методу WhatsApp
class WhatsAppDecryptingStream implements StreamInterface
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
     * Внутренний буфер для накопления расшифрованного текста
     * @var string
     */
    private $plainBuffer = '';

    /**
     * Внутренний буфер для накопления зашифрованного текста
     * @var string
     */
    private $cipherBuffer = '';   

    /**
     * Исходный ключ шифрования
     * @var string
     */
    private $mediaKey;
    
    /**
     * Исходный вектор инифиализации метода шифрования
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
     * В данном случае содержит входной зашифрованный текст
     * @var StreamInterface
     */
    private $stream;
    
    /**
     * Накапливает прочитанный зашифрованный текст, чтобы проверить его подпись на финальной стадии чтения
     * @var string
     */
    private $fullEncryptedText = '';  
    
    /**
     * Текущий вектор инициализации шифрования AES-CBC
     * На нулевой позиции равен входящему iv
     * Далее приравнивается последнему использованному закодированному блоку
     * @var string
     */
    private $currentIv; 

    //Конструктор класса
    //  baseStream - ссылка на базовый поток данных
    //  mediaKey - входной ключ шифрования по методу WhatsApp
    //  mediaType - тип шифруемых данных
    public function __construct(
        StreamInterface $cipherText,        
        string $mediaKey,        
        string $mediaType
    ) {
        $this->stream = $cipherText;
        $this->mediaKey = $mediaKey; 
        //Расширяем исходный ключ и вычисляем от него iv, cipherKey, macKey
        $this->expandKeyAndGetParts($mediaType);           
        $this->currentIv = $this->iv;
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
    
    //Проверяем совпадает ли mac входящего текста с вычисленным значением mac
    private function testWhatsAppDecryptLogic() 
    {                 
        $this->stream->seek(-10,SEEK_END);
        $inMac = $this->stream->read(10);                
        $hmac = hash_hmac('sha256', $this->iv . $this->fullEncryptedText, $this->macKey, true);
        $mac = substr($hmac,0,10);            
        if ($mac!=$inMac) {
            throw new \RuntimeException("Ошибка подписи шифрования");
        }
    }

    //Возвращает true, если указатель чтения достиг конца расшифрованных данных
    public function eof()
    {
        return $this->cipherBuffer === '' && $this->stream->eof();
    }

    //Возвращает полный размер расшифрованных данных
    //В данном случае без полной последовательной расшивфровки это невозможно    
    public function getSize(): ?int
    {        
        return null;
    }

    //Поток расшифровки не допускает запись в него
    public function isWritable(): bool
    {
        return false;
    }

    //Возвращает часть расшифрованного текста длинной length байт     
    public function read($length): string
    {
        //Если в буфере plainBuffer недостаточно данных для вывода, тогда расширим его новыми раскодированными данными
        if ($length > strlen($this->plainBuffer)) {            
            $this->plainBuffer .= $this->decryptBlock(
                self::BLOCK_SIZE * ceil(($length - strlen($this->plainBuffer)) / self::BLOCK_SIZE)
            );
        }

        //Возвращаем не более указанного числа байт
        $data = substr($this->plainBuffer, 0, $length);
        
        //Возвращённые байты изымаются из буфера, чтобы не возвращать их повторно
        $this->plainBuffer = substr($this->plainBuffer, $length);

        return $data ? $data : '';
    }

    //Реализация seek вроде необязательна, пока откажемся от неё
    public function isSeekable(): bool
    {
        return false;
    } 

    //Читает из зашифрованного потока блок текста длинной length и расшифровывает его 
    //  методом AES-CBC
    //По мере достижения области mac - расшифровка прекращается и выполняется проверка подписи
    private function decryptBlock(int $length): string
    {        
        //Если входной поток прочитан до конца, то результат - ''
        if ($this->cipherBuffer === '' && $this->stream->eof()) {
            return '';
        }

        //Читает нужную часть текста из зашифрованного потока или берёт её из буфера
        $cipherText = $this->cipherBuffer;
        while (strlen($cipherText) < $length && !$this->stream->eof()) {
            $cipherText .= $this->stream->read($length - strlen($cipherText));
        }
        
        if ($this->stream->tell()>=$this->stream->getSize()-10) {
            //Прочитан участок, зашифрованный AES-CBC. Оставшася часть содержит mac.
            //Проверим.
            
            //Дополнительное чтение, чтобы точно считать mac
            $cipherText .= $this->stream->read(self::BLOCK_SIZE);            
            
            //mac Не должен участвовать в последней операции расшифровки
            $cipherText = substr($cipherText, 0, -10); 
            
            $this->fullEncryptedText .= $cipherText; 
            $this->testWhatsAppDecryptLogic();            
            if (strlen($cipherText)==0) {  
                //Если читали мелкими порциями, то можем тут получить пустой текст для расшифровки
                return '';
            }
        } else {
            $this->fullEncryptedText .= $cipherText; 
        }
                
        //При вызове метода шифрования важно получить сырые данные
        $options = OPENSSL_RAW_DATA;        
        $this->cipherBuffer = $this->stream->read(self::BLOCK_SIZE);                        
        if (!($this->cipherBuffer === '' && $this->stream->eof())) {
            $options |= OPENSSL_ZERO_PADDING;
        }

        //Вызов функции расшифровки AES-CBC
        //Вектор инициализации берётся из currentIv, где он предварительно 
        //  получается равным результату расшифровки предыдущего блока 
        $plaintext = openssl_decrypt(
            $cipherText,
            "aes-256-cbc",
            $this->cipherKey,
            $options,
            $this->currentIv
        );                

        //Выводим ошибку в случае проблем с расшифровкой
        if ($plaintext === false) {              
            throw new \RuntimeException("Unable to decrypt $cipherText with an initialization vector"
                . " of {$this->currentIv}. Please ensure you have provided the correct algorithm, initialization vector, and key.");
        }

        //Запомнимаем новый вектор инициализации равным 
        //  последнему использованному зашифрованному блоку
        $this->currentIv = substr($cipherText, self::BLOCK_SIZE * -1);   

        return $plaintext;
    }
}
