
<?php
declare(strict_types=1);

const APP_NAME = 'SUNNY SECURE CIPHER TOOL';
const PBKDF2_ITERATIONS = 600000;
const SALT_LENGTH = 16;
const IV_LENGTH = 16;
const MAC_LENGTH = 32;

$encMsg = '';
$encResult = '';
$decCipher = '';
$decResult = '';
$httpStatus = 200;

/**
 * Escape output before inserting it into HTML.
 */
function e(string $value): string
{
    return htmlspecialchars(
        $value,
        ENT_QUOTES | ENT_SUBSTITUTE,
        'UTF-8'
    );
}

/**
 * Derive separate encryption and authentication keys.
 */
function deriveKeys(string $passcode, string $salt): array
{
    $derived = hash_pbkdf2(
        'sha256',
        $passcode,
        $salt,
        PBKDF2_ITERATIONS,
        64,
        true
    );

    return [
        substr($derived, 0, 32),  // AES-256 key
        substr($derived, 32, 32)  // HMAC key
    ];
}

/**
 * Encrypt a message and return the VSM1 ciphertext.
 *
 * Format:
 * VSM1 + salt + IV + ciphertext + HMAC
 */
function encryptMessage(string $message, string $passcode): string
{
    if (strlen($passcode) < 8) {
        throw new InvalidArgumentException(
            'Passcode must contain at least 8 characters.'
        );
    }

    $salt = random_bytes(SALT_LENGTH);
    $iv = random_bytes(IV_LENGTH);

    [$encryptionKey, $macKey] = deriveKeys($passcode, $salt);

    $encrypted = openssl_encrypt(
        $message,
        'aes-256-cbc',
        $encryptionKey,
        OPENSSL_RAW_DATA,
        $iv
    );

    if ($encrypted === false) {
        throw new RuntimeException('Encryption failed.');
    }

    $header = 'VSM1' . $salt . $iv . $encrypted;

    $mac = hash_hmac('sha256', $header, $macKey, true);

    return base64_encode($header . $mac);
}

/**
 * Authenticate and decrypt a VSM1 ciphertext.
 */
function decryptMessage(string $encoded, string $passcode): string
{
    if ($passcode === '') {
        throw new InvalidArgumentException('Passcode is required.');
    }

    $raw = base64_decode($encoded, true);

    // Minimum size: 4-byte marker + 16-byte salt
    // + 16-byte IV + 16-byte AES block + 32-byte HMAC.
    if (
        $raw === false ||
        strlen($raw) < 84 ||
        substr($raw, 0, 4) !== 'VSM1'
    ) {
        throw new InvalidArgumentException('Invalid ciphertext.');
    }

    $salt = substr($raw, 4, SALT_LENGTH);
    $iv = substr($raw, 20, IV_LENGTH);

    $macOffset = strlen($raw) - MAC_LENGTH;

    $encrypted = substr(
        $raw,
        36,
        $macOffset - 36
    );

    $receivedMac = substr($raw, $macOffset);

    // AES-CBC ciphertext must contain complete blocks.
    if (
        strlen($encrypted) === 0 ||
        strlen($encrypted) % 16 !== 0
    ) {
        throw new InvalidArgumentException('Invalid ciphertext.');
    }

    [$encryptionKey, $macKey] = deriveKeys($passcode, $salt);

    $authenticatedData = substr($raw, 0, $macOffset);

    $expectedMac = hash_hmac(
        'sha256',
        $authenticatedData,
        $macKey,
        true
    );

    // Verify authenticity before attempting decryption.
    if (!hash_equals($expectedMac, $receivedMac)) {
        throw new InvalidArgumentException('Decryption failed.');
    }

    $original = openssl_decrypt(
        $encrypted,
        'aes-256-cbc',
        $encryptionKey,
        OPENSSL_RAW_DATA,
        $iv
    );

    if ($original === false) {
        throw new InvalidArgumentException('Decryption failed.');
    }

    return $original;
}

/**
 * Handle the encryption form.
 */
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';
    $passcode = $_POST['passcode'] ?? '';

    if (!is_string($passcode)) {
        $passcode = '';
    }

    if ($action === 'encrypt') {
        $message = $_POST['message'] ?? '';
        $encMsg = is_string($message) ? $message : '';

        try {
            if ($encMsg === '') {
                throw new InvalidArgumentException(
                    'Enter a message to encrypt.'
                );
            }

            if (!mb_check_encoding($encMsg, 'UTF-8')) {
                throw new InvalidArgumentException(
                    'Enter a valid UTF-8 message.'
                );
            }

            $encResult = encryptMessage($encMsg, $passcode);
        } catch (Throwable $error) {
            $encResult = $error instanceof InvalidArgumentException
                ? $error->getMessage()
                : 'An internal error occurred.';
            $httpStatus = 400;
        }
    } elseif ($action === 'decrypt') {
        $cipher = $_POST['ciphertext'] ?? '';
        $decCipher = is_string($cipher) ? trim($cipher) : '';

        try {
            if ($decCipher === '') {
                throw new InvalidArgumentException(
                    'Enter ciphertext to decrypt.'
                );
            }

            $decResult = decryptMessage($decCipher, $passcode);
        } catch (Throwable $error) {
            $decResult =
                'Decryption failed. Check your ciphertext and passcode.';
            $httpStatus = 400;
        }
    }
}

http_response_code($httpStatus);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">

    <title>SUNNY Secure Cipher Tool</title>

    <style>
        * {
            box-sizing: border-box;
        }

        body {
            font-family: Arial, sans-serif;
            background: #f0f4f8;
            padding: 20px;
            max-width: 650px;
            margin: auto;
            color: #222;
        }

        h2 {
            text-align: center;
            color: #123456;
        }

        .subtitle {
            text-align: center;
            margin-bottom: 25px;
        }

        .card {
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 8px #0002;
            margin-bottom: 20px;
        }

        input, textarea {
            display: block;
            width: 100%;
            padding: 12px;
            margin: 8px 0 15px;
            border: 1px solid #ccc;
            border-radius: 5px;
            font-size: 15px;
            font-family: inherit;
        }

        textarea {
            resize: vertical;
        }

        button {
            background: #0759b5;
            color: white;
            padding: 12px 18px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            width: 100%;
            font-size: 16px;
        }

        button:hover {
            background: #06458b;
        }

        .result {
            background: #e8f0f7;
            padding: 12px;
            border-radius: 5px;
            overflow-wrap: anywhere;
            white-space: pre-wrap;
            line-height: 1.5;
        }

        .error {
            color: #b00020;
        }

        .note {
            font-size: 13px;
            color: #555;
            line-height: 1.6;
        }

        label {
            font-weight: bold;
            font-size: 14px;
        }
    </style>
</head>

<body>

    <h2>SUNNY SECURE CIPHER TOOL</h2>

    <p class="subtitle">
        Encrypt and decrypt messages using a passcode.
    </p>

    <div class="card">
        <h3>Encrypt Message</h3>

        <form method="POST" action="">
            <input type="hidden" name="action" value="encrypt">

            <label for="message">Enter your message:</label>

            <textarea
                id="message"
                name="message"
                rows="4"
                required
            ><?= e($encMsg) ?></textarea>

            <label for="enc-passcode">Create a passcode:</label>

            <input
                id="enc-passcode"
                type="password"
                name="passcode"
                minlength="8"
                required
                autocomplete="new-password"
            >

            <button type="submit">Encrypt Message</button>
        </form>

        <?php if ($encResult !== ''): ?>
            <h4>
                <?= $httpStatus === 200
                    ? 'Encrypted Result'
                    : 'Encryption Error' ?>
            </h4>

            <div class="result"
                role="status"><?= e($encResult) ?></div>
        <?php endif; ?>
    </div>

    <div class="card">
        <h3>Decrypt Message</h3>

        <form method="POST" action="">
            <input type="hidden" name="action" value="decrypt">

            <label for="ciphertext">Enter ciphertext:</label>

            <textarea
                id="ciphertext"
                name="ciphertext"
                rows="4"
                required
            ><?= e($decCipher) ?></textarea>

            <label for="dec-passcode">
                Enter the same passcode:
            </label>

            <input
                id="dec-passcode"
                type="password"
                name="passcode"
                required
                autocomplete="current-password"
            >

            <button type="submit">Decrypt Message</button>
        </form>

        <?php if ($decResult !== ''): ?>
            <h4>Decryption Result</h4>

            <div
                class="result <?= $httpStatus !== 200 ? 'error' : '' ?>"
                role="status"
            ><?= e($decResult) ?></div>
        <?php endif; ?>
    </div>

    <p class="note">
        Keep your passcode safe. The original message cannot be
        recovered without the correct passcode. This tool uses
        AES-256-CBC with HMAC-SHA256 authentication
    </p>

</body>
</html>
