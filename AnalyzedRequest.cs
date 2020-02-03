using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Filter
{
    class AnalyzedRequest
    {
        private bool isRequestSafe;
        private string suspiciousValues;
        private string safeValues;

        public bool IsRequestSafe { get => isRequestSafe; set => isRequestSafe = value; }
        public string SuspiciousValues { get => suspiciousValues; set => suspiciousValues = value; }
        public string SafeValues { get => safeValues; set => safeValues = value; }
    }
}
