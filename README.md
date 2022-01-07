## Trivy Result Parser
### Visão Geral
Esta é uma ferramenta interna criada para realizar o parse do resultado de relatórios gerados pelo Trivy referentes ao scan de vulnerabilidades de containeres e vulnerabilidades de arquivos de configuração. 




### Exemplos de uso da ferramenta
```sh
trivy_result_parser --report-file=./report.json --low=20 [--option=number]
trivy_result_parser --report-file=./report.json --low=20 --critical=0 [--option=number]
```

**OPTIONS**:

```sh
--report-file   Path de um arquivo JSON contendo o report de vulnerabilidades gerado pelo Trivy. Podendo ser o report de vulnerabilidades de imagens docker ou reporte de vulnerabilidades de arquivos de configuração .YML | .YAML

--unknown       Número de vulnerabilidades do tipo unknown aceitas.

--low           Número de vulnerabilidades do tipo low aceitas.

--medium        Número de vulnerabilidades do tipo medium aceitas.

--high          Número de vulnerabilidades do tipo high aceitas.

--critical      Número de vulnerabilidades do tipo critical aceitas.
```



### Execução local da ferramenta

Exemplo de execução local da ferramenta:

```sh
npm install
node trivy_result_parser.js --report-file=./report.json --low=20 [--option=number]
node trivy_result_parser.js --report-file=./report.json --low=20 --critical=0 [--option=number]
```



Exemplo de build local da ferramenta:

```sh
npm run build
```

Após rodar o build serão gerados 3 binários no diretório ./dist da aplicação, sendo eles:

```sh
trivy_result_parser-linux
trivy_result_parser-macos
trivy_result_parser-win.exe
```







### Exemplo de uso do Trivy para geração dos reports lidos pelo utilitário
Scan de vulnerabilidades em imagens docker:
```sh
trivy image -f json -o /path-to-report/report-name.json image-name:tag
```



Scan de vulnerabilidades em arquivos de configuração:

```sh
trivy config -f json -o /path-to-report/report-name.json /path-to-config-file
```