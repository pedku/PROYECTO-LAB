let dataTable;
let horariodata = false;
let usuario = false;
let horariodataTable;
let labs;
let labsTable;
let usuarioTable;
let dataTableIsInitialized = false;
let dataTable_viewer;
let viewer = false;
let logs = false;
let dataTable_logs;

const profesOptions = {
    //scrollX: "2000px",
    lengthMenu: [5, 10, 15, 20, 100, 200, 500],
    columnDefs: [
        { className: "centered", targets: [0, 1, 2, 3] },
        { orderable: false, targets: [3] },
        { searchable: false, targets: [3] }
        //{ width: "50%", targets: [0] }
    ],
    pageLength: 10,
    destroy: true,
    language: {
        lengthMenu: "Mostrar _MENU_ registros por página",
        zeroRecords: "Ningún usuario encontrado",
        info: "Mostrando de _START_ a _END_ de un total de _TOTAL_ registros",
        infoEmpty: "Ningún usuario encontrado",
        infoFiltered: "(filtrados desde _MAX_ registros totales)",
        search: "Buscar:",
        loadingRecords: "Cargando...",
        paginate: {
            first: "Primero",
            last: "Último",
            next: "Siguiente",
            previous: "Anterior"
        }
    }

};

const HorarioOptions = {
    //scrollX: "2000px",
    lengthMenu: [5, 10, 15, 20, 100, 200, 500],
    columnDefs: [
        { className: "centered", targets: [0, 1, 2, 3, 4, 5, 6] },
        { orderable: false, targets: [6] },
        { searchable: false, targets: [6] }
        //{ width: "50%", targets: [0] }
    ],
    pageLength: 10,
    destroy: true,
    language: {
        lengthMenu: "Mostrar _MENU_ registros por página",
        zeroRecords: "Ningún usuario encontrado",
        info: "Mostrando de _START_ a _END_ de un total de _TOTAL_ registros",
        infoEmpty: "Ningún usuario encontrado",
        infoFiltered: "(filtrados desde _MAX_ registros totales)",
        search: "Buscar:",
        loadingRecords: "Cargando...",
        paginate: {
            first: "Primero",
            last: "Último",
            next: "Siguiente",
            previous: "Anterior"
        }
    }
};

const HorarioOptions_viewer = {

    //scrollX: "2000px",
    lengthMenu: [5, 10, 15, 20, 100, 200, 500],
    columnDefs: [
        { className: "centered", targets: [0, 1, 2, 3, 4, 5] }
        //{ width: "50%", targets: [0] }
    ],
    pageLength: 10,
    destroy: true,
    language: {
        lengthMenu: "Mostrar _MENU_ registros por página",
        zeroRecords: "Ningún usuario encontrado",
        info: "Mostrando de _START_ a _END_ de un total de _TOTAL_ registros",
        infoEmpty: "Ningún usuario encontrado",
        infoFiltered: "(filtrados desde _MAX_ registros totales)",
        search: "Buscar:",
        loadingRecords: "Cargando...",
        paginate: {
            first: "Primero",
            last: "Último",
            next: "Siguiente",
            previous: "Anterior"
        }
    }
};

const usuarioOptions = {
    //scrollX: "2000px",
    lengthMenu: [5, 10, 15, 20, 100, 200, 500],
    columnDefs: [
        { className: "centered", targets: [0, 1, 2, 3] },
        { orderable: false, targets: [3] },
        { searchable: false, targets: [3] }
        //{ width: "50%", targets: [0] }
    ],
    pageLength: 5,
    destroy: true,
    language: {
        lengthMenu: "Mostrar _MENU_ registros por página",
        zeroRecords: "Ningún usuario encontrado",
        info: "Mostrando de _START_ a _END_ de un total de _TOTAL_ registros",
        infoEmpty: "Ningún usuario encontrado",
        infoFiltered: "(filtrados desde _MAX_ registros totales)",
        search: "Buscar:",
        loadingRecords: "Cargando...",
        paginate: {
            first: "Primero",
            last: "Último",
            next: "Siguiente",
            previous: "Anterior"
        }
    }
};

const logsOptions = {
    //scrollX: "2000px",
    lengthMenu: [5, 10, 15, 20, 100, 200, 500],
    columnDefs: [
        { className: "centered", targets: [0, 1, 2] }

        //{ width: "50%", targets: [0] }
    ],
    pageLength: 10,
    destroy: true,
    language: {
        lengthMenu: "Mostrar _MENU_ registros por página",
        zeroRecords: "Ningún usuario encontrado",
        info: "Mostrando de _START_ a _END_ de un total de _TOTAL_ registros",
        infoEmpty: "Ningún usuario encontrado",
        infoFiltered: "(filtrados desde _MAX_ registros totales)",
        search: "Buscar:",
        loadingRecords: "Cargando...",
        paginate: {
            first: "Primero",
            last: "Último",
            next: "Siguiente",
            previous: "Anterior"
        }
    }

};

const labsOptions = {
    scrollY: 300,
    scrollX: true,
    scrollCollapse: true,
    paging: false,
    autoFill: true,
    lengthMenu: [5, 10, 15, 20, 100, 200, 500],
    columnDefs: [
        { className: "centered", targets: [0, 1, 2] },
        { orderable: false, targets: [3] }
    ],
    pageLength: 5,
    destroy: true,
    
    language: {
        zeroRecords: "Ningún usuario encontrado",
        info: "Mostrando de _START_ a _END_ de un total de _TOTAL_ registros",
        infoEmpty: "Ningún usuario encontrado",
        infoFiltered: "(filtrados desde _MAX_ registros totales)",
        search: "Buscar:",
        loadingRecords: "Cargando...",
        paginate: {
            first: "Primero",
            last: "Último",
            next: "Siguiente",
            previous: "Anterior"
        }
    }
}

const initDataTable_labs = async () => {
    $('[id^=scheduleTable]').each(function() {
        var tableId = $(this).attr('id');
        if ($.fn.DataTable.isDataTable('#' + tableId)) {
            $('#' + tableId).DataTable().destroy();
        }
        $('#' + tableId).DataTable(labsOptions);

        
    });
   




};

const initDataTable = async () => {
    if (dataTableIsInitialized) {
        dataTable.destroy();
    }

    dataTable = $("#dataTable_horario").DataTable(HorarioOptions);
    dataTableIsInitialized = true;
};

const initDataTable_usuario = async () => {
    if (usuario) {
        usuarioTable.destroy();
    }

    usuarioTable = $("#dataTable_usuarios").DataTable(usuarioOptions);
    usuario = true;
};

const initDataTable_horario = async () => {
    if (horariodata) {
        horariodataTable.destroy();
    }

    horariodataTable = $("#dataTables_profes").DataTable(profesOptions);
    horariodata = true;
};

const initDataTable_logs = async () => {
    if (dataTable_logs) {
        dataTable_logs.destroy();
    }

    dataTable_logs = $("#dataTable_logs").DataTable(logsOptions);
    logs = true;
};

const initDataTable_viewer = async () => {
    if (dataTable_viewer) {
        dataTable_viewer.destroy();
    }
    dataTable_viewer = $("#dataTable_viewer").DataTable(HorarioOptions_viewer);
    viewer = true;
};




window.addEventListener("load", async () => {
    await initDataTable();
    await initDataTable_horario();
    await initDataTable_usuario();
    await initDataTable_viewer();
    await initDataTable_logs();
    await initDataTable_labs();
   






    // Función para volver a enlazar los eventos de los botones
    function bindEditButtons() {
        $('.btn-primary[data-toggle="modal"]').off('click').on('click', function() {
            let scheduleId = $(this).data('target').replace('#editModal', '');
            $('#editModal' + scheduleId).modal('show');
        });

        // Volver a enlazar los eventos de los botones de cerrar del modal
        $('.close').off('click').on('click', function() {
            $(this).closest('.modal').modal('hide');
        });
    }

    // Enlazar los eventos de los botones después de que DataTables haya terminado de inicializarse
    dataTable.on('draw', function() {
        bindEditButtons();
    });

    // Enlazar los eventos de los botones en la carga inicial
    bindEditButtons();
});

$.ajaxSetup({
    beforeSend: function(xhr, settings) {
        if (!/^(GET|HEAD|OPTIONS|TRACE)$/i.test(settings.type) && !this.crossDomain) {
            xhr.setRequestHeader("X-CSRFToken", "{{ csrf_token() }}");
        }
    }
});



