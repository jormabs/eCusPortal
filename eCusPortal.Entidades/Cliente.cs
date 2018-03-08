using System;
using System.Collections.Generic;
using System.Text;

namespace eCusPortal.Entidades
{
    public class Cliente
    {
        public int IdCliente { get; set; }
        public int IdTipoDocumento { get; set; }
        public string Documento { get; set; }
        public string Nombre1 { get; set; }
        public string Nombre2 { get; set; }
        public string Apellido1 { get; set; }
        public string Apellido2 { get; set; }
        public string Email { get; set; }
        public string TelefonoResidencia { get; set; }
        public string TelefonoMovil { get; set; }
        public string TelefonoOtro { get; set; }
        public DateTime fechaRegistro { get; set; }
        public string EstadoCivil { get; set; }
        public string Sexo { get; set; }
        public DateTime? FechaNacimiento { get; set; }
        public DateTime? UltimaActualizacion { get; set; }
        public int CanalActualizacion { get; set; }
        public byte? Estrato { get; set; }
        public bool EnvioSms { get; set; }
        public bool EnvioMail { get; set; }
        public string Email2 { get; set; }
        public EstadoMail EstadoMail { get; set; }
        public string EmailAlterno { get; set; }
        public MedioTransporte MedioTransporte { get; set; }
        public string PlacaVehiculo { get; set; }
        public bool Extranjero { get; set; }
        public int CantidadHijosMayoresEdad { get; set; }
        public bool Activo { get; set; }
        public string UserId { get; set; }
    }
}
