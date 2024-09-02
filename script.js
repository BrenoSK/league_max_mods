document.getElementById('cardNumber').addEventListener('input', function(e) {
    let value = e.target.value.replace(/\D/g, ''); // Remove tudo que não for número
    value = value.match(/.{1,4}/g)?.join(' ') || value; // Insere espaço a cada 4 dígitos
    e.target.value = value;
});

document.getElementById('expiryDate').addEventListener('input', function(e) {
    let value = e.target.value.replace(/\D/g, ''); // Remove tudo que não for número
    if (value.length > 2) {
        value = value.slice(0, 2) + '/' + value.slice(2, 4); // Adiciona '/' após os 2 primeiros dígitos
    }
    e.target.value = value;
});

document.getElementById('cvv').addEventListener('input', function(e) {
    let value = e.target.value.replace(/\D/g, ''); // Remove tudo que não for número
    e.target.value = value.slice(0, 3); // Limita o CVV a 3 dígitos
});

document.getElementById('saveButton').addEventListener('click', function() {
    const cardNumber = document.getElementById('cardNumber').value;
    const cardName = document.getElementById('cardName').value;
    const expiryDate = document.getElementById('expiryDate').value;
    const cvv = document.getElementById('cvv').value;

    const data = {
        "Número do Cartão": cardNumber,
        "Nome do Titular": cardName,
        "Data de Expiração": expiryDate,
        "Código de Segurança": cvv
    };

    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'dados_pagamento.json';
    a.click();
    URL.revokeObjectURL(url);
});
