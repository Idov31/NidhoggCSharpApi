using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using static NidhoggCSharpApi.NidhoggApi;

namespace NidhoggCSharpApi
{
    internal class Program
    {
        static void Main(string[] args)
        {
            NidhoggApi nidhogg;

            try
            {
                nidhogg = new NidhoggApi();
            }
            catch (NidhoggApiException e)
            {
                Console.WriteLine(e.Message);
                return;
            }
        }
    }
}
