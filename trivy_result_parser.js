const yargs = require('yargs/yargs');
const { hideBin } = require('yargs/helpers');
const args = yargs(hideBin(process.argv)).argv;
const fs = require('fs');

function printHelp () {
    console.log(`
    Exemplos de uso:
    trivy_result_parser --report-file=./report.json --low=20 [--option=number]
    trivy_result_parser --report-file=./report.json --low=20 --critical=0 [--option=number]

    OPTIONS:
    --report-file   Path de um arquivo JSON contendo o report de vulnerabilidades gerado pelo Trivy.
                    Podendo ser o report de vulnerabilidades de imagens docker ou reporte de 
                    vulnerabilidades de arquivos de configuração .YML | .YAML
    --unknown       Número de vulnerabilidades do tipo unknown aceitas.
    --low           Número de vulnerabilidades do tipo low aceitas.
    --medium        Número de vulnerabilidades do tipo medium aceitas.
    --high          Número de vulnerabilidades do tipo high aceitas.
    --critical      Número de vulnerabilidades do tipo critical aceitas.
    `)
}

// Path to report file
const reportFile = args['report-file'];

// Condições de falha
const limit = {
    unknown: args.unknown,
    low: args.low,
    medium: args.medium,
    high: args.high,
    critical: args.critical
}

if (reportFile == undefined || (Object.values(limit).every(x => x === undefined))) {
    printHelp()
    process.exit(1);
}

fs.readFile(reportFile, 'utf8' , (err, data) => {
    if (err) {
      console.error(err)
      process.exit(1)
    }
    
    var parsedData = JSON.parse(data);
    // Chave utilizada para realizar a análise de resultados baseada no tipo de artefato do report trivy.
    var keyusada = null;
    if (parsedData.ArtifactType ==  'container_image') {
        keyusada = 'Vulnerabilities'
    } else if (parsedData.ArtifactType ==  'filesystem') {
        keyusada = 'Misconfigurations'
    } else {
        console.log('Arquivo inválido!')
        console.log('O arquivo deve seguir o formato de artefato "container_image" ou "filesystem"')
        process.exit(1)
    }

    var results = parsedData.Results;
    var vulnerabilitiesListByTarget = []
    var vulnerabilitiesTotal = {
        unknown: 0,
        low: 0,
        medium: 0,
        high: 0,
        critical: 0
    }

    for (var i in results) {
        var currentResults = results[i]
        var target = currentResults.Target
        var resultClass = currentResults.Class
        var type = currentResults.Type

        var vulnerabilities = {
            unknown: 0,
            low: 0,
            medium: 0,
            high: 0,
            critical: 0
        }


        if (keyusada in currentResults) {
            for(var j in currentResults[keyusada]) {
                var currentVulnerabilitie = currentResults[keyusada][j]
                switch (currentVulnerabilitie.Severity) {
                    case 'UNKNOWN':
                        ++vulnerabilities.unknown;
                        ++vulnerabilitiesTotal.unknown;
                        break;
                    case 'LOW':
                        ++vulnerabilities.low;
                        ++vulnerabilitiesTotal.low;
                        break;
                    case 'MEDIUM':
                        ++vulnerabilities.medium;
                        ++vulnerabilitiesTotal.medium;
                        break;
                    case 'HIGH':
                        ++vulnerabilities.high;
                        ++vulnerabilitiesTotal.high;
                        break;
                    case 'CRITICAL':
                        ++vulnerabilities.critical;
                        ++vulnerabilitiesTotal.critical;
                        break;
                    default:
                        ++vulnerabilities.unknown;
                        ++vulnerabilitiesTotal.unknown;
                        break;
                }
            }

            var currentVulnerabilitieResultByTarget = {
                target: target,
                class: resultClass,
                type: type,
                vulnerabilities: vulnerabilities
            }

            vulnerabilitiesListByTarget.push(currentVulnerabilitieResultByTarget)

        }

    }

    var reportSuccess = true;

    for (var key in limit) {
        if (limit[key]) {
            const limitValue = parseInt(limit[key])
            if (isNaN(limitValue)) {
                console.log('\x1b[33m%s\x1b[0m', `O valor do argumento --${key} deve ser um número inteiro positivo. O mesmo será ignorado!`);
                continue;
            }
            if (limitValue < 0) {
                console.log('\x1b[33m%s\x1b[0m', `O valor do argumento --${key} deve ser um número inteiro positivo. O mesmo será ignorado!`);
                continue;
            }
            if (vulnerabilitiesTotal[key] > limitValue) {
                reportSuccess = false;
            }
        }
    }

    if (vulnerabilitiesListByTarget.length == 0) {
        console.log('Scan de vulnerabilidades realizado com sucesso!')
        console.log('\x1b[32m%s\x1b[0m', 'Status: Aprovado');
        console.log('Mensagem: Nenhuma vulnerabilidade encontrada.')
        console.log('Para mais detalhes consulte o relatório de vulnerabilidades anexado no resultado desta pipeline!')
        process.exit(0)
    } else {
        if (reportSuccess == true) {
            console.log('Scan de vulnerabilidades realizado com sucesso!')
            console.log('\x1b[32m%s\x1b[0m', 'Status: Aprovado');
            console.log('Mensagem: Foram encontradas vulnerabilidades porém estão dentro dos valores estabelecidos.')
            console.log('Resumo das vulnerabilidades encontradas por target:')
            console.log(vulnerabilitiesListByTarget)
            console.log('Resumo de todas as vulnerabilidades encontradas:')
            console.log(vulnerabilitiesTotal)
            console.log('Para mais detalhes consulte o relatório de vulnerabilidades anexado no resultado desta pipeline!')
            process.exit(0)
        } else {
            console.log('Scan de vulnerabilidades realizado com sucesso!')
            console.log('\x1b[31m%s\x1b[0m', 'Status: Reprovado');
            console.log('Mensagem: O número de vulnerabilidades encontrado está acima dos valores estabelecidos.')
            console.log('Resumo das vulnerabilidades encontradas por target:')
            console.log(vulnerabilitiesListByTarget)
            console.log('Resumo de todas as vulnerabilidades encontradas:')
            console.log(vulnerabilitiesTotal)
            console.log('Para mais detalhes consulte o relatório de vulnerabilidades anexado no resultado desta pipeline!')
            process.exit(1)
        }

    }

})
