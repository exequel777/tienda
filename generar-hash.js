/**
 * ============================================
 * GENERADOR DE HASH BCRYPT
 * ============================================
 * Ejecutar con: npm run generar-hash
 *
 * Este script toma la contraseña del archivo .env,
 * genera un hash con bcrypt (10 rondas de salt)
 * y te indica exactamente qué pegar en tu .env.
 */

const bcrypt = require('bcrypt');
const fs = require('fs');
const readline = require('readline');

const RONDAS_SALT = 10;

const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});

rl.question('Ingresa la contraseña que quieres hashear: ', (password) => {
    rl.close();

    if (!password || password.length < 6) {
        console.error('Error: La contraseña debe tener al menos 6 caracteres.');
        process.exit(1);
    }

    console.log(`\nGenerando hash con ${RONDAS_SALT} rondas de salt...`);

    bcrypt.hash(password, RONDAS_SALT, (err, hash) => {
        if (err) {
            console.error('Error al generar el hash:', err);
            process.exit(1);
        }

        console.log('\n============================================');
        console.log('  HASH GENERADO EXITOSAMENTE');
        console.log('============================================');
        console.log('\nCopia la siguiente línea y pégala en tu archivo .env:\n');
        console.log(`ADMIN_PASSWORD_HASH=${hash}`);
        console.log('\n============================================');

        // Intentar actualizar el .env automáticamente
        try {
            const envPath = __dirname + '/.env';
            let envContent = fs.readFileSync(envPath, 'utf8');

            envContent = envContent.replace(
                /ADMIN_PASSWORD_HASH=.*/,
                `ADMIN_PASSWORD_HASH=${hash}`
            );

            fs.writeFileSync(envPath, envContent, 'utf8');
            console.log('\nArchivo .env actualizado automáticamente con el nuevo hash.');
        } catch (e) {
            console.log('\nNo se pudo actualizar .env automáticamente.');
            console.log('Copia manualmente la línea de arriba.');
        }
    });
});
