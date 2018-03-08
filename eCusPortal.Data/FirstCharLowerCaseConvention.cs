using Microsoft.Data.Edm.Library;
using System;
using System.Collections.Generic;
using System.Text;

namespace eCusPortal.Data
{
    public class FirstCharLowerCaseConvention : IStoreModelConvention<EdmProperty>
    {
        public void Apply(EdmProperty property, DbModel model)
        {
            property.Name = property.Name.Substring(0, 1).ToLower()
                          + property.Name.Substring(1);
        }
    }
}
