# Implementação de Telemetria In-Band (INT) em P4

## Objetivo

Implementar um mecanismo de In-Band Network Telemetry (INT) em uma rede programável P4, permitindo que informações de monitoramento sejam adicionadas aos pacotes durante o seu percurso pela rede e posteriormente extraídas pela aplicação receptora.

## Alterações no Arquivo `basic.p4`

### Criação dos Cabeçalhos de Telemetria

Foram criados dois novos tipos de cabeçalho:

* **INT Master (cabeçalho pai):** responsável por indicar a presença de telemetria no pacote e armazenar informações de controle, como a quantidade de cabeçalhos filhos adicionados e o tamanho total da área de telemetria.
* **INT Slave (cabeçalho filho):** inserido por cada switch percorrido pelo pacote e responsável por armazenar informações locais do dispositivo.

Cada cabeçalho filho armazena:

* ID do switch;
* Porta de entrada;
* Porta de saída;
* Timestamp de entrada do pacote no switch.

### Modificações no Parser

O parser foi alterado para reconhecer pacotes contendo telemetria. Após extrair o cabeçalho IPv4, o campo `protocol` é verificado. Quando seu valor é `253`, o parser desvia para a leitura do cabeçalho `INT Master` e, em seguida, realiza a extração de todos os cabeçalhos `INT Slave` presentes no pacote.

### Modificações no Ingress

O pipeline de ingresso foi modificado para:

1. Verificar se o pacote já possui um cabeçalho INT;
2. Caso não possua, criar e inicializar o cabeçalho `INT Master`, além de alterar o campo `ipv4.protocol` para `253`;
3. Inserir um novo cabeçalho `INT Slave` contendo as informações de telemetria do switch atual;
4. Atualizar a quantidade de cabeçalhos filhos e o tamanho total da telemetria;
5. Ajustar o tamanho total do pacote IPv4 após a inclusão dos novos cabeçalhos.

## Alterações no `receive.py`

O programa receptor foi modificado para reconhecer pacotes cujo campo `IP Protocol` seja igual a `253`. Após receber o pacote, a aplicação:

1. Extrai o cabeçalho `INT Master`;
2. Determina a quantidade de cabeçalhos `INT Slave`;
3. Percorre todos os cabeçalhos de telemetria presentes;
4. Recupera as informações de cada salto da rede;
5. Separa o payload original da aplicação dos dados de telemetria;
6. Exibe em uma interface textual:

   * IP de origem e destino;
   * Protocolo encapsulado original;
   * Quantidade de bytes de telemetria;
   * Mensagem transportada;
   * Lista de switches percorridos e suas respectivas métricas.

## Funcionamento Geral

Quando um pacote ingressa na rede, o primeiro switch adiciona o cabeçalho INT caso ele ainda não exista. Cada switch subsequente acrescenta um novo cabeçalho filho contendo suas informações locais de monitoramento. Ao chegar ao host destino, o programa `receive.py` identifica e remove logicamente os cabeçalhos de telemetria, apresentando ao usuário as condições observadas ao longo de todo o caminho percorrido pelo pacote.
