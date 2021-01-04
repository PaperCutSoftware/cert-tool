#!/usr/bin/env node

/*
 * Copyright (c) 2019 PaperCut Software International Pty. Ltd.
 *
 * https://www.papercut.com
 *
 * Use of this source code is governed by an GNU GPLv3 license.
 * See the project's LICENSE file for more information.
 */
const forge = require("node-forge");
const fs = require("fs");
const chalk = require("chalk");
const yargs = require("yargs");
const packageJson = require("./package.json");
const { networkInterfaces } = require("os");

// Yargs declaration for handling command-line arguments
const options = yargs
  .usage(
    `cert-tool v${packageJson.version}\nUsage: cert-tool -t <certificate type>`
  )
  .option("f", {
    alias: "file",
    describe: "The name of the certificate file(s)",
    type: "string"
  })
  .option("t", {
    alias: "type",
    describe: "The module type to generate the certificate for",
    choices: ["pem", "pfx"],
    type: "string",
    demandOption: true
  })
  .option("o", {
    alias: "output",
    describe: "The output directory for the certificates",
    type: "string"
  })
  .option("c", {
    alias: "combined",
    describe:
      "Whether to combine certificate and key in the same file(PEM certificate type only)",
    type: "boolean"
  })
  .option("p", {
    alias: "password",
    describe: "The password for our pfx file",
    type: "string"
  })
  .option("i", {
    alias: "ip",
    describe:
      "Sets the IP of subject alternate name, if null it will be set to your external IP",
    type: "string"
  })
  .option("h", {
    alias: "hostname",
    describe: "Sets the hostname of the subject alternate name",
    type: "string"
  })
  .check(function(argv, options) {
    if (argv.type.toLowerCase() === "pfx") {
      if (argv.combined) {
        throw new Error("Cannot use combine flag on PFX certificate");
      } else if ( argv.password === undefined || argv.password.length == 0) {
        throw new Error("Please enter a valid password for PFX certificate");
      }
    }
    return true;
  }).argv;

// Helper function(s)
const getLocalExternalIP = () => {
  return []
    .concat(...Object.values(networkInterfaces()))
    .filter(details => details.family === "IPv4" && !details.internal)
    .pop().address;
};
// ---

// Extract file name out other set default
const fileName = options.file ? options.file : "certificate";

// generate a keypair
console.log("Generating 2048-bit key-pair...");
var keys = forge.pki.rsa.generateKeyPair(2048);
console.log("Key-pair created.");

// create a certificate
console.log("Creating self-signed certificate...");
var cert = forge.pki.createCertificate();
cert.publicKey = keys.publicKey;
// Serial isn't important in this instance
cert.serialNumber = "01";
cert.validity.notBefore = new Date();
cert.validity.notAfter = new Date();
cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);
var attrs = [
  {
    name: "commonName",
    value: "localhost"
  },
  {
    name: "countryName",
    value: "AU"
  },
  {
    shortName: "ST",
    value: "Victoria"
  },
  {
    name: "localityName",
    value: "Melbourne"
  },
  {
    name: "organizationName",
    value: "PaperCut Software"
  },
  {
    shortName: "OU",
    value: "Development"
  }
];
cert.setSubject(attrs);
cert.setIssuer(attrs);
// Determine alt names based on our cli flags
var altNames = [];
// Always add localhost entries
altNames.push(
  {
    type: 2, // DNS
    value: "localhost"
  },
  {
    type: 7, // IP
    ip: "127.0.0.1"
  }
);
// Use provided ip
if (options.ip) {
  altNames.push({
    type: 7, // IP
    ip: options.ip
  });
  // Determine external IP and use that
} else {
  if (options.ip === "") {
    altNames.push({
      type: 7, // IP
      ip: getLocalExternalIP()
    });
  }
}
if (options.hostname) {
  altNames.push({
    type: 2, // DNS
    value: options.hostname
  });
}

cert.setExtensions([
  {
    name: "subjectAltName",
    altNames: altNames
  }
]);
// self-sign certificate
cert.sign(keys.privateKey);
console.log("Certificate created.");

// Use sync because we need this directory before we do anything
if (!fs.existsSync(`${process.cwd()}/certificates`)) {
  fs.mkdirSync(`${process.cwd()}/certificates`);
  console.log("Creating certificates directory");
} else {
  console.log("Found certificates directory");
}

if (options.type.toUpperCase() === "PEM") {
  const pemPkey = forge.pki.privateKeyToPem(keys.privateKey);
  const pemCert = forge.pki.certificateToPem(cert);
  if (options.combined) {
    // Create stream writer
    const writeStream = fs.createWriteStream(
      `${process.cwd()}/certificates/${fileName}.pem`
    );

    writeStream.write(pemPkey, "binary");
    writeStream.write(pemCert, "binary");

    writeStream.on("error", err => {
      console.error(chalk.red(err));
    });
    // the finish event is emitted when all data has been flushed from the stream
    writeStream.on("finish", () => {
      console.log(
        chalk.green(
          `Successfully saved certificate: ${process.cwd()}/certificates/${fileName}.pem`
        )
      );
    });
    // close the stream
    writeStream.end();
  } else {
    // Use async writing as it has more elegant error handling
    fs.writeFile(
      `${process.cwd()}/certificates/${fileName}_key.pem`,
      pemPkey,
      err => {
        if (err) {
          console.error(chalk.red(err));
          return;
        }
        console.log(
          chalk.green(
            `Successfully saved pem key: ${process.cwd()}/certificates/certificates/${fileName}_key.pem`
          )
        );
      }
    );
    fs.writeFile(
      `${process.cwd()}/certificates/${fileName}_cert.pem`,
      pemCert,
      err => {
        if (err) {
          console.error(chalk.red(err));
          return;
        }
        console.log(
          chalk.green(
            `Successfully saved pem certificate: ${process.cwd()}/certificates/certificates/${fileName}_cert.pem`
          )
        );
      }
    );
  }
} else if (options.type.toUpperCase() === "PFX") {
  console.log("Outputting as PFX format");
  var newPkcs12Asn1 = forge.pkcs12.toPkcs12Asn1(
    keys.privateKey,
    [cert],
    options.password,
    {
      algorithm: "3des"
    }
  );
  var newPkcs12Der = forge.asn1.toDer(newPkcs12Asn1).getBytes();
  fs.writeFile(
    `${process.cwd()}/certificates/${fileName}.pfx`,
    newPkcs12Der,
    "binary",
    err => {
      if (err) {
        console.error(chalk.red(err));
        return;
      }
      console.log(
        chalk.green(
          `Successfully saved certificate: ${process.cwd()}/certificates/${fileName}.pfx`
        )
      );
    }
  );
}
