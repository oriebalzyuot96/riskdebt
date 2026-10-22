using System.Data.SqlClient;
using System.Runtime.Serialization.Formatters.Binary;

public class UserController
{
    public void Configure(CorsPolicyBuilder b)
    {
        b.AllowAnyOrigin();
    }

    public void Find(string name)
    {
        var cmd = new SqlCommand("SELECT * FROM Users WHERE Name = '" + name + "'");
    }

    public object Load(Stream s)
    {
        var f = new BinaryFormatter();
        return f.Deserialize(s);
    }
}
